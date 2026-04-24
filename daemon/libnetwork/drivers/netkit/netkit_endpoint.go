//go:build linux

package netkit

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/containerd/log"
	"github.com/moby/moby/v2/daemon/libnetwork/driverapi"
	"github.com/moby/moby/v2/daemon/libnetwork/netlabel"
	"github.com/moby/moby/v2/daemon/libnetwork/ns"
	"github.com/moby/moby/v2/daemon/libnetwork/portmapperapi"
	"github.com/moby/moby/v2/daemon/libnetwork/types"
	"github.com/moby/moby/v2/errdefs"
	"github.com/moby/moby/v2/internal/sliceutil"
)

func (d *driver) CreateEndpoint(ctx context.Context, nid, eid string, ifInfo driverapi.InterfaceInfo, epOptions map[string]any) error {
	_ = ctx
	_ = epOptions

	if err := validateID(nid, eid); err != nil {
		return err
	}

	n, err := d.getNetwork(nid)
	if err != nil {
		return errdefs.System(fmt.Errorf("network id %q not found", nid))
	}

	ep := &endpoint{
		id:     eid,
		nid:    nid,
		addr:   ifInfo.Address(),
		addrv6: ifInfo.AddressIPv6(),
	}
	if ifInfo.MacAddress() != nil {
		return errors.New("netkit interfaces do not support custom mac address assignment")
	}

	if err := d.storeUpdate(ep); err != nil {
		return fmt.Errorf("failed to save netkit endpoint %.7s to store: %v", ep.id, err)
	}

	n.addEndpoint(ep)
	return nil
}

func warnUnsupportedEndpointOptions(ctx context.Context, epOptions map[string]any) {
	if opt, ok := epOptions[netlabel.PortMap]; ok {
		if ports, ok := opt.([]types.PortBinding); ok && len(ports) > 0 {
			log.G(ctx).Warn("netkit driver does not support port mappings")
		}
	}
	if opt, ok := epOptions[netlabel.ExposedPorts]; ok {
		if ports, ok := opt.([]types.TransportPort); ok && len(ports) > 0 {
			log.G(ctx).Warn("netkit driver does not support port exposures")
		}
	}
}

func (d *driver) DeleteEndpoint(nid, eid string) error {
	if err := validateID(nid, eid); err != nil {
		return err
	}

	n := d.network(nid)
	if n == nil {
		return fmt.Errorf("network id %q not found", nid)
	}

	ep, err := n.endpoint(eid)
	if err != nil {
		return err
	}

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
	if err := removeEndpointRoutes(ep); err != nil {
		log.G(context.TODO()).WithError(err).Warnf("failed to remove host routes for endpoint %.7s", ep.id)
	}
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
		log.G(context.TODO()).Warnf("failed to remove netkit endpoint %.7s from store: %v", ep.id, err)
	}

	n.deleteEndpoint(ep.id)
	return nil
}

func parseConnectivityOptions(cOptions map[string]any) (*connectivityConfiguration, error) {
	if cOptions == nil {
		return nil, nil
	}

	cc := &connectivityConfiguration{}

	if opt, ok := cOptions[netlabel.PortMap]; ok {
		pbs, ok := opt.([]types.PortBinding)
		if !ok {
			return nil, types.InvalidParameterErrorf("invalid port mapping data in connectivity configuration: %v", opt)
		}
		if err := validatePortBindings(pbs); err != nil {
			return nil, err
		}
		cc.PortBindings = sliceutil.Map(pbs, func(pb types.PortBinding) portmapperapi.PortBindingReq {
			return portmapperapi.PortBindingReq{PortBinding: pb.Copy()}
		})
	}

	if opt, ok := cOptions[netlabel.ExposedPorts]; ok {
		ports, ok := opt.([]types.TransportPort)
		if !ok {
			return nil, types.InvalidParameterErrorf("invalid exposed ports data in connectivity configuration: %v", opt)
		}
		cc.ExposedPorts = ports
	}

	if len(cc.PortBindings) == 0 && len(cc.ExposedPorts) == 0 {
		return nil, nil
	}
	return cc, nil
}

func validatePortBindings(pbs []types.PortBinding) error {
	for _, pb := range pbs {
		switch pb.Proto {
		case types.TCP, types.UDP:
		default:
			return types.InvalidParameterErrorf("unsupported published port protocol %q for netkit pure eBPF port mapping", strings.ToLower(pb.Proto.String()))
		}
	}
	return nil
}

func validateBindingFamilies(ep4, ep6 *net.IPNet, cfg *connectivityConfiguration) error {
	if cfg == nil {
		return nil
	}
	for _, pb := range cfg.PortBindings {
		if len(pb.HostIP) == 0 {
			continue
		}
		if pb.HostIP.To4() != nil {
			if ep4 == nil {
				return types.InvalidParameterErrorf("netkit pure eBPF port mapping only supports same-family published ports")
			}
			continue
		}
		if ep6 == nil {
			return types.InvalidParameterErrorf("netkit pure eBPF port mapping only supports same-family published ports")
		}
	}
	return nil
}
