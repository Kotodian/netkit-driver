//go:build linux

package netkit

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/moby/moby/v2/daemon/libnetwork/driverapi"
	"github.com/moby/moby/v2/daemon/libnetwork/netlabel"
	"github.com/moby/moby/v2/daemon/libnetwork/netutils"
	"github.com/moby/moby/v2/daemon/libnetwork/ns"
	"github.com/moby/moby/v2/daemon/libnetwork/types"
	"github.com/vishvananda/netlink"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sys/unix"
)

var (
	defaultV4Route = &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
	defaultV6Route = &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}
)

var hostLinkByName = func(name string) (netlink.Link, error) {
	return ns.NlHandle().LinkByName(name)
}

var replaceHostRoute = func(route *netlink.Route) error {
	return ns.NlHandle().RouteReplace(route)
}

var deleteHostRoute = func(route *netlink.Route) error {
	return ns.NlHandle().RouteDel(route)
}

type createdInContainerSetter interface {
	SetCreatedInContainer(bool)
}

var generateIfaceName = func() (string, error) {
	return netutils.GenerateIfaceName(ns.NlHandle(), hostIfPrefix, hostIfLen)
}

func (d *driver) Join(ctx context.Context, nid, eid string, sboxKey string, jinfo driverapi.JoinInfo, epOpts, sbOpts map[string]any) (retErr error) {
	ctx, span := otel.Tracer("").Start(ctx, "libnetwork.drivers.netkit.Join", trace.WithAttributes(
		attribute.String("nid", nid),
		attribute.String("eid", eid),
		attribute.String("sboxKey", sboxKey)))
	defer span.End()

	n, err := d.getNetwork(nid)
	if err != nil {
		return err
	}
	ep, err := n.endpoint(eid)
	if err != nil {
		return err
	}
	ep.extConnConfig, err = parseConnectivityOptions(sbOpts)
	if err != nil {
		return err
	}
	if err := validateBindingFamilies(ep.addr, ep.addrv6, ep.extConnConfig); err != nil {
		return err
	}

	hostIfName, err := generateIfaceName()
	if err != nil {
		return fmt.Errorf("error generating a host interface name: %w", err)
	}
	containerIfName, err := generateIfaceName()
	if err != nil {
		return fmt.Errorf("error generating a container interface name: %w", err)
	}
	if err := createNetkitFn(hostIfName, containerIfName, n.config.Parent, sboxKey, ep.mac, n.config.EnableBigTCP); err != nil {
		return err
	}
	defer cleanupFailedJoin(hostIfName, &retErr)

	ep.srcName = containerIfName
	ep.hostIf = hostIfName
	markCreatedInContainer(jinfo)

	if err := setJoinGateways(jinfo, ep, n.config, eid); err != nil {
		return err
	}
	if err := programEndpointRoutes(ep); err != nil {
		return err
	}
	if err := d.upsertEgressEndpointDatapath(ctx, n, ep); err != nil {
		return err
	}
	defer func() {
		if retErr != nil {
			_ = d.removeEgressEndpointDatapath(ep)
		}
	}()
	if hasPublishedPorts(ep.extConnConfig) {
		d.configNetwork.Lock()
		rt, err := d.acquireParentRuntimeLocked(ctx, publishedPortScopeKey(n))
		if err == nil {
			err = rt.AddEndpoint(ctx, publishedEndpointConfigForEndpoint(ep))
		}
		if err != nil {
			_ = d.releaseParentRuntimeLocked(ctx, publishedPortScopeKey(n))
			d.configNetwork.Unlock()
			return err
		}
		ep.publishedParent = publishedPortScopeKey(n)
		d.configNetwork.Unlock()
		defer func() {
			if retErr == nil || ep.publishedParent == "" {
				return
			}
			d.configNetwork.Lock()
			if pr := d.parents[ep.publishedParent]; pr != nil {
				_ = pr.runtime.DelEndpoint(context.TODO(), publishedEndpointConfigForEndpoint(ep))
				_ = d.releaseParentRuntimeLocked(context.TODO(), ep.publishedParent)
			}
			ep.publishedParent = ""
			d.configNetwork.Unlock()
		}()
	}
	if err := d.attachEndpointDatapath(ctx, ep); err != nil {
		return err
	}
	defer func() {
		if retErr != nil {
			_ = d.detachEndpointDatapath(ep)
		}
	}()
	if err := d.upsertLocalEndpointDatapaths(ep); err != nil {
		_ = d.removeLocalEndpointDatapaths(ep)
		return err
	}
	defer func() {
		if retErr != nil {
			_ = d.removeLocalEndpointDatapaths(ep)
		}
	}()
	jinfo.DisableGatewayService()

	if err := jinfo.InterfaceName().SetNames(containerIfName, containerVethPrefix, netlabel.GetIfname(epOpts)); err != nil {
		return err
	}
	if err := d.storeUpdate(ep); err != nil {
		return fmt.Errorf("failed to save netkit endpoint %.7s to store: %v", ep.id, err)
	}
	return nil
}

func cleanupFailedJoin(hostIfName string, retErr *error) {
	if *retErr == nil {
		return
	}
	link, err := ns.NlHandle().LinkByName(hostIfName)
	if err == nil {
		_ = ns.NlHandle().LinkDel(link)
	}
}

func markCreatedInContainer(jinfo driverapi.JoinInfo) {
	if iface := jinfo.InterfaceName(); iface != nil {
		if setter, ok := iface.(createdInContainerSetter); ok {
			setter.SetCreatedInContainer(true)
		}
	}
}

func setJoinGateways(jinfo driverapi.JoinInfo, ep *endpoint, config *configuration, eid string) error {
	if config.Internal {
		return nil
	}
	if ep.addr != nil {
		if err := jinfo.AddStaticRoute(defaultV4Route, types.CONNECTED, nil); err != nil {
			return fmt.Errorf("failed to add ipv4 connected default route for endpoint %s: %w", eid, err)
		}
	}
	if ep.addrv6 != nil {
		if err := jinfo.AddStaticRoute(defaultV6Route, types.CONNECTED, nil); err != nil {
			return fmt.Errorf("failed to add ipv6 connected default route for endpoint %s: %w", eid, err)
		}
	}
	return nil
}

func (d *driver) Leave(nid, eid string) error {
	d.configNetwork.Lock()
	defer d.configNetwork.Unlock()

	n, err := d.getNetwork(nid)
	if err != nil {
		return err
	}
	ep, err := n.endpoint(eid)
	if err != nil {
		return err
	}

	if err := d.removeLocalEndpointDatapathsLocked(ep); err != nil {
		return err
	}
	if err := d.releaseEndpointPublishedPortsLocked(context.TODO(), ep); err != nil {
		return err
	}

	if err := removeEndpointRoutes(ep); err != nil {
		return err
	}
	if err := d.removeEgressEndpointDatapathLocked(ep); err != nil {
		return err
	}
	if err := d.storeUpdate(ep); err != nil {
		return fmt.Errorf("failed to save netkit endpoint %.7s during leave: %v", ep.id, err)
	}
	return nil
}

func programEndpointRoutes(ep *endpoint) error {
	routes, err := endpointRoutes(ep)
	if err != nil {
		return err
	}
	for _, route := range routes {
		routeCopy := route
		if err := replaceHostRoute(&routeCopy); err != nil {
			return fmt.Errorf("program host route for endpoint %s: %w", ep.id, err)
		}
	}
	return nil
}

func removeEndpointRoutes(ep *endpoint) error {
	routes, err := endpointRoutes(ep)
	if err != nil {
		return err
	}
	for _, route := range routes {
		routeCopy := route
		if err := deleteHostRoute(&routeCopy); err != nil && !errors.Is(err, unix.ESRCH) {
			return fmt.Errorf("remove host route for endpoint %s: %w", ep.id, err)
		}
	}
	return nil
}

func endpointRoutes(ep *endpoint) ([]netlink.Route, error) {
	if ep == nil || ep.hostIf == "" {
		return nil, nil
	}
	link, err := hostLinkByName(ep.hostIf)
	if err != nil {
		return nil, fmt.Errorf("resolve host link %q: %w", ep.hostIf, err)
	}
	linkIndex := link.Attrs().Index
	var routes []netlink.Route
	if dst := hostRouteDestination(ep.addr); dst != nil {
		routes = append(routes, netlink.Route{
			LinkIndex: linkIndex,
			Scope:     netlink.SCOPE_LINK,
			Dst:       dst,
		})
	}
	if dst := hostRouteDestination(ep.addrv6); dst != nil {
		routes = append(routes, netlink.Route{
			LinkIndex: linkIndex,
			Scope:     netlink.SCOPE_LINK,
			Dst:       dst,
		})
	}
	return routes, nil
}

func hostRouteDestination(addr *net.IPNet) *net.IPNet {
	if addr == nil || addr.IP == nil {
		return nil
	}
	maskBits := 128
	if addr.IP.To4() != nil {
		maskBits = 32
	}
	return &net.IPNet{
		IP:   types.GetIPNetCopy(addr).IP,
		Mask: net.CIDRMask(maskBits, maskBits),
	}
}

func getSubnetForIP(ip *net.IPNet, subnets []*ipSubnet) *ipSubnet {
	for _, s := range subnets {
		_, snet, err := net.ParseCIDR(s.SubnetIP)
		if err != nil {
			return nil
		}
		i, _ := snet.Mask.Size()
		j, _ := ip.Mask.Size()
		if i != j {
			continue
		}
		if snet.Contains(ip.IP) {
			return s
		}
	}
	return nil
}
