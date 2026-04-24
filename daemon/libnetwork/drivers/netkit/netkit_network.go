//go:build linux

package netkit

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/containerd/log"
	"github.com/moby/moby/v2/daemon/libnetwork/driverapi"
	"github.com/moby/moby/v2/daemon/libnetwork/netlabel"
	"github.com/moby/moby/v2/daemon/libnetwork/netutils"
	"github.com/moby/moby/v2/daemon/libnetwork/ns"
	"github.com/moby/moby/v2/daemon/libnetwork/options"
	"github.com/moby/moby/v2/daemon/libnetwork/types"
	"github.com/moby/moby/v2/errdefs"
	"github.com/vishvananda/netlink"
)

type gwMode string

const (
	gwModeNAT       gwMode = "nat"
	gwModeRouted    gwMode = "routed"
	gwModeIsolated  gwMode = "isolated"
	gwModeNATUnprot gwMode = "nat-unprotected"
)

var generateProbeIfaceName = func() (string, error) {
	return netutils.GenerateIfaceName(ns.NlHandle(), probeIfPrefix, probeIfLen)
}

var addProbeLink = func(link netlink.Link) error {
	return ns.NlHandle().LinkAdd(link)
}

var lookupProbeLink = func(name string) (netlink.Link, error) {
	return ns.NlHandle().LinkByName(name)
}

var deleteProbeLink = func(link netlink.Link) error {
	return ns.NlHandle().LinkDel(link)
}

func newGwMode(mode string) (gwMode, error) {
	switch mode {
	case "", string(gwModeNAT):
		return gwModeNAT, nil
	case string(gwModeRouted):
		return gwModeRouted, nil
	case string(gwModeIsolated):
		return gwModeIsolated, nil
	case string(gwModeNATUnprot):
		return gwModeNATUnprot, nil
	default:
		return "", types.InvalidParameterErrorf("invalid gateway mode %q", mode)
	}
}

func (m gwMode) routed() bool {
	return m == gwModeRouted
}

func (d *driver) CreateNetwork(ctx context.Context, nid string, option map[string]any, nInfo driverapi.NetworkInfo, ipV4Data, ipV6Data []driverapi.IPAMData) error {
	if err := d.probeKernel(); err != nil {
		return err
	}
	if err := validateIPAMPools(option, ipV4Data, ipV6Data); err != nil {
		return err
	}

	config, err := parseNetworkOptions(nid, option)
	if err != nil {
		return err
	}
	config.processIPAM(ipV4Data, ipV6Data)

	foundExisting, err := d.createNetwork(config)
	if err != nil {
		return err
	}
	if foundExisting {
		return types.InternalMaskableErrorf("restoring existing network %s", config.ID)
	}

	if err := d.storeUpdate(config); err != nil {
		d.deleteNetwork(config.ID)
		log.G(ctx).Debugf("encountered an error rolling back a network create for %s: %v", config.ID, err)
		return err
	}
	return nil
}

func validateIPAMPools(option map[string]any, ipV4Data, ipV6Data []driverapi.IPAMData) error {
	if v, ok := option[netlabel.EnableIPv4]; ok && v.(bool) {
		if len(ipV4Data) == 0 || ipV4Data[0].Pool.String() == "0.0.0.0/0" {
			return errdefs.InvalidParameter(errors.New("ipv4 pool is empty"))
		}
	}
	if v, ok := option[netlabel.EnableIPv6]; ok && v.(bool) {
		if len(ipV6Data) == 0 || ipV6Data[0].Pool.String() == "::/0" {
			return errdefs.InvalidParameter(errors.New("ipv6 pool is empty"))
		}
	}
	return nil
}

func (d *driver) GetSkipGwAlloc(options.Generic) (ipv4, ipv6 bool, _ error) {
	return true, true, nil
}

func (d *driver) createNetwork(config *configuration) (bool, error) {
	if config.Parent != "" {
		return false, errdefs.InvalidParameter(errors.New("netkit L3-native mode does not support the parent option"))
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if _, ok := d.networks[config.ID]; ok {
		return true, nil
	}

	d.networks[config.ID] = &network{
		id:        config.ID,
		driver:    d,
		endpoints: map[string]*endpoint{},
		config:    config,
	}
	return false, nil
}

func (d *driver) DeleteNetwork(nid string) error {
	n := d.network(nid)
	if n == nil {
		return fmt.Errorf("network id %s not found", nid)
	}

	for _, ep := range n.endpoints {
		if err := d.removeLocalEndpointDatapaths(ep); err != nil {
			log.G(context.TODO()).WithError(err).Warnf("failed to remove netkit local endpoint datapath state for endpoint %.7s", ep.id)
		}
		if err := d.detachEndpointDatapath(ep); err != nil {
			log.G(context.TODO()).WithError(err).Warnf("failed to detach netkit endpoint datapath for endpoint %.7s", ep.id)
		}
		d.configNetwork.Lock()
		if err := d.releaseEndpointPublishedPortsLocked(context.TODO(), ep); err != nil {
			log.G(context.TODO()).WithError(err).Warnf("failed to release netkit published ports for endpoint %.7s", ep.id)
		}
		if err := d.removeEgressEndpointDatapathLocked(ep); err != nil {
			log.G(context.TODO()).WithError(err).Warnf("failed to remove netkit egress datapath state for endpoint %.7s", ep.id)
		}
		d.configNetwork.Unlock()
		linkName := ep.hostIf
		if linkName == "" {
			linkName = ep.srcName
		}
		if link, err := ns.NlHandle().LinkByName(linkName); err == nil {
			if err := ns.NlHandle().LinkDel(link); err != nil {
				log.G(context.TODO()).WithError(err).Warnf("failed to delete interface (%s)'s link on endpoint (%s) delete", linkName, ep.id)
			}
		}
		if err := d.storeDelete(ep); err != nil {
			log.G(context.TODO()).WithError(err).Warnf("failed to remove netkit endpoint %.7s from store", ep.id)
		}
	}

	d.deleteNetwork(nid)
	if err := d.storeDelete(n.config); err != nil {
		return fmt.Errorf("error deleting id %s from datastore: %v", nid, err)
	}
	return nil
}

func parseNetworkOptions(id string, option options.Generic) (*configuration, error) {
	config := defaultConfiguration()

	if genData, ok := option[netlabel.GenericData]; ok && genData != nil {
		cfg, err := parseNetworkGenericOptions(genData)
		if err != nil {
			return nil, err
		}
		config = cfg
	}
	if val, ok := option[netlabel.Internal]; ok {
		if internal, ok := val.(bool); ok && internal {
			config.Internal = true
		}
	}
	if config.Parent != "" {
		return nil, errdefs.InvalidParameter(errors.New("netkit L3-native mode does not support the parent option"))
	}

	config.ID = id
	return config, nil
}

func parseNetworkGenericOptions(data any) (*configuration, error) {
	switch opt := data.(type) {
	case *configuration:
		return opt, nil
	case map[string]string:
		return newConfigFromLabels(opt)
	default:
		return nil, types.InvalidParameterErrorf("unrecognized network configuration format: %v", opt)
	}
}

func newConfigFromLabels(labels map[string]string) (*configuration, error) {
	config := defaultConfiguration()
	for label, value := range labels {
		if label == parentOpt {
			config.Parent = value
			continue
		}
		if err := config.applyBridgeLabel(label, value); err != nil {
			return nil, err
		}
	}
	return config, nil
}

func (config *configuration) processIPAM(ipamV4Data, ipamV6Data []driverapi.IPAMData) {
	for _, ipd := range ipamV4Data {
		subnet := &ipSubnet{SubnetIP: ipd.Pool.String()}
		if ipd.Gateway != nil {
			subnet.GwIP = ipd.Gateway.String()
		}
		config.Ipv4Subnets = append(config.Ipv4Subnets, subnet)
	}
	for _, ipd := range ipamV6Data {
		subnet := &ipSubnet{SubnetIP: ipd.Pool.String()}
		if ipd.Gateway != nil {
			subnet.GwIP = ipd.Gateway.String()
		}
		config.Ipv6Subnets = append(config.Ipv6Subnets, subnet)
	}
}

func (d *driver) probeKernel() error {
	d.probeOnce.Do(func() {
		probe := d.probe
		if probe == nil {
			probe = d.probeNetkitSupport
		}
		if err := probe(); err != nil {
			d.probeErr = errdefs.NotImplemented(fmt.Errorf("netkit unsupported (requires Linux 6.7+): %w", err))
		}
	})
	return d.probeErr
}

func (d *driver) probeNetkitSupport() (retErr error) {
	ifName, err := generateProbeIfaceName()
	if err != nil {
		return err
	}
	peerName, err := generateProbeIfaceName()
	if err != nil {
		return err
	}

	probe := &netlink.Netkit{
		LinkAttrs:  netlink.LinkAttrs{Name: ifName, TxQLen: 0},
		Mode:       netlink.NETKIT_MODE_L3,
		Policy:     netlink.NETKIT_POLICY_BLACKHOLE,
		PeerPolicy: netlink.NETKIT_POLICY_BLACKHOLE,
		Scrub:      netlink.NETKIT_SCRUB_DEFAULT,
		PeerScrub:  netlink.NETKIT_SCRUB_DEFAULT,
	}
	probe.SetPeerAttrs(&netlink.LinkAttrs{Name: peerName, TxQLen: 0})

	if err := addProbeLink(probe); err != nil {
		return err
	}
	cleanupLink := netlink.Link(probe)
	defer func() {
		if cleanupLink == nil {
			return
		}
		if err := deleteProbeLink(cleanupLink); err != nil {
			retErr = errors.Join(retErr, err)
		}
	}()

	link, err := lookupProbeLink(ifName)
	if err != nil {
		return err
	}
	cleanupLink = link
	return probeNetkitAttach(link.Attrs().Index)
}

func gatewayAddr(ip *net.IPNet) net.IP {
	if ip == nil {
		return nil
	}
	addr := types.GetIPNetCopy(ip)
	if addr == nil || addr.IP == nil {
		return nil
	}
	if v4 := addr.IP.To4(); v4 != nil {
		return net.IPv4zero
	}
	return net.IPv6zero
}
