//go:build linux

package netkit

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"

	"github.com/moby/moby/v2/daemon/libnetwork/drivers/bridge"
	"github.com/moby/moby/v2/daemon/libnetwork/drvregistry"
	"github.com/moby/moby/v2/daemon/libnetwork/netutils"
	"github.com/moby/moby/v2/daemon/libnetwork/portmapperapi"
	"github.com/moby/moby/v2/daemon/libnetwork/types"
)

func hasPublishedPorts(cfg *connectivityConfiguration) bool {
	return cfg != nil && len(cfg.PortBindings) != 0
}

var isV6Listenable = netutils.IsV6Listenable

func egressEndpointConfigForNetwork(cfg *configuration, ep *endpoint) (egressEndpointConfig, bool) {
	if cfg == nil || ep == nil || cfg.Internal || !cfg.EnableIPMasquerade {
		return egressEndpointConfig{}, false
	}

	config := egressEndpointConfig{
		HostIf: ep.hostIf,
		Addr:   cloneIPNet(ep.addr),
		Addrv6: cloneIPNet(ep.addrv6),
	}
	if ep.addr != nil && !cfg.GwModeIPv4.routed() {
		if cfg.HostIPv4 != nil {
			config.HostIPv4 = append(net.IP(nil), cfg.HostIPv4...)
		} else {
			config.MasqueradeIPv4 = true
		}
	} else {
		config.Addr = nil
	}
	if ep.addrv6 != nil && !cfg.GwModeIPv6.routed() {
		if cfg.HostIPv6 != nil {
			config.HostIPv6 = append(net.IP(nil), cfg.HostIPv6...)
		} else {
			config.MasqueradeIPv6 = true
		}
	} else {
		config.Addrv6 = nil
	}
	if !config.MasqueradeIPv4 && !config.MasqueradeIPv6 && config.HostIPv4 == nil && config.HostIPv6 == nil {
		return egressEndpointConfig{}, false
	}
	return config, true
}

func publishedPortScopeKey(n *network) string {
	if n == nil {
		return ""
	}
	return n.id
}

func endpointDatapathKey(ep *endpoint) string {
	if ep == nil {
		return ""
	}
	return ep.nid + "/" + ep.id
}

func publishedEndpointConfigForEndpoint(ep *endpoint) publishedEndpointConfig {
	if ep == nil {
		return publishedEndpointConfig{}
	}
	return publishedEndpointConfig{
		HostIf: ep.hostIf,
		Addr:   cloneIPNet(ep.addr),
		Addrv6: cloneIPNet(ep.addrv6),
	}
}

func (d *driver) upsertEgressEndpointDatapath(ctx context.Context, n *network, ep *endpoint) error {
	config, ok := egressEndpointConfigForNetwork(n.config, ep)
	if !ok {
		return nil
	}

	d.configNetwork.Lock()
	defer d.configNetwork.Unlock()

	return d.upsertEgressEndpointDatapathLocked(ctx, n, ep, config)
}

func (d *driver) upsertEgressEndpointDatapathLocked(ctx context.Context, n *network, ep *endpoint, config egressEndpointConfig) error {
	if d.datapathEndpoints == nil {
		d.datapathEndpoints = map[string]struct{}{}
	}

	datapath, created, err := d.acquirePublishedPortDatapathLocked(ctx, publishedPortScopeKey(n))
	if err != nil {
		return err
	}
	if err := datapath.UpsertEgressEndpoint(config); err != nil {
		if created && len(d.parents) == 0 && len(d.datapathEndpoints) == 0 {
			_ = datapath.Close()
			d.datapath = nil
			d.sharedDatapathLinks = map[string]struct{}{}
		}
		return err
	}
	d.datapathEndpoints[endpointDatapathKey(ep)] = struct{}{}
	return nil
}

func (d *driver) removeEgressEndpointDatapath(ep *endpoint) error {
	if ep == nil {
		return nil
	}

	d.configNetwork.Lock()
	defer d.configNetwork.Unlock()

	return d.removeEgressEndpointDatapathLocked(ep)
}

func (d *driver) removeEgressEndpointDatapathLocked(ep *endpoint) error {
	if d.datapath == nil {
		return nil
	}

	config := egressEndpointConfig{
		Addr:   cloneIPNet(ep.addr),
		Addrv6: cloneIPNet(ep.addrv6),
	}
	err := d.datapath.RemoveEgressEndpoint(config)
	if d.datapathEndpoints != nil {
		delete(d.datapathEndpoints, endpointDatapathKey(ep))
	}
	if len(d.parents) == 0 && len(d.datapathEndpoints) == 0 {
		err = errors.Join(err, d.datapath.Close())
		d.datapath = nil
		d.sharedDatapathLinks = map[string]struct{}{}
	}
	return err
}

func (d *driver) ProgramExternalConnectivity(ctx context.Context, nid, eid string, gw4Id, gw6Id string) error {
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

	if !hasPublishedPorts(ep.extConnConfig) {
		return nil
	}

	if ep.publishedParent == "" {
		rt, err := d.acquireParentRuntimeLocked(ctx, publishedPortScopeKey(n))
		if err != nil {
			return err
		}
		if err := rt.AddEndpoint(ctx, publishedEndpointConfigForEndpoint(ep)); err != nil {
			_ = d.releaseParentRuntimeLocked(ctx, publishedPortScopeKey(n))
			return err
		}
		ep.publishedParent = publishedPortScopeKey(n)
	}

	pr := d.parents[ep.publishedParent]
	if pr == nil {
		return fmt.Errorf("published port runtime for parent %q not found", ep.publishedParent)
	}

	desired := portBindingMode{routed: true}
	if gw4Id == eid {
		desired.ipv4 = true
	}
	if gw6Id == eid || (gw6Id == "" && gw4Id == eid && ep.addrv6 != nil) {
		desired.ipv6 = true
	}
	if ep.portBindingState == desired {
		return nil
	}

	req := publishedPortRequest{
		Addr:           ep.addr,
		Addrv6:         ep.addrv6,
		PortBindings:   ep.extConnConfig.PortBindings,
		Current:        ep.portMapping,
		CurrentMode:    ep.portBindingState,
		DesiredMode:    desired,
		DisableNATIPv4: n.config.GwModeIPv4.routed(),
		DisableNATIPv6: n.config.GwModeIPv6.routed(),
	}
	portMapping, err := pr.runtime.ReconcilePortBindings(ctx, req)
	if err != nil {
		return err
	}

	ep.portMapping = portMapping
	ep.portBindingState = desired
	pr.runtime.ClearConntrack(ep.addr, ep.addrv6, ep.portMapping)
	if err := d.storeUpdate(ep); err != nil {
		return fmt.Errorf("failed to save netkit endpoint %.7s during external connectivity update: %v", ep.id, err)
	}
	return nil
}

func (d *driver) releaseEndpointPublishedPortsLocked(ctx context.Context, ep *endpoint) error {
	if ep == nil || ep.publishedParent == "" {
		return nil
	}

	parent := ep.publishedParent
	pr := d.parents[parent]
	if pr == nil {
		ep.portMapping = nil
		ep.portBindingState = portBindingMode{}
		ep.publishedParent = ""
		return nil
	}

	if len(ep.portMapping) != 0 {
		if err := pr.runtime.ReleasePortBindings(ctx, ep.portMapping); err != nil {
			return err
		}
	}
	if err := pr.runtime.DelEndpoint(ctx, publishedEndpointConfigForEndpoint(ep)); err != nil {
		return err
	}
	if err := d.releaseParentRuntimeLocked(ctx, parent); err != nil {
		return err
	}

	ep.portMapping = nil
	ep.portBindingState = portBindingMode{}
	ep.publishedParent = ""
	return nil
}

func (d *driver) acquireParentRuntimeLocked(ctx context.Context, parent string) (publishedPortRuntime, error) {
	if pr, ok := d.parents[parent]; ok {
		pr.refs++
		return pr.runtime, nil
	}

	if d.newPortRuntime != nil {
		rt, err := d.newPortRuntime(ctx, parent)
		if err != nil {
			return nil, err
		}
		d.parents[parent] = &parentRuntime{
			parent:  parent,
			runtime: rt,
			refs:    1,
		}
		return rt, nil
	}

	datapath, created, err := d.acquirePublishedPortDatapathLocked(ctx, parent)
	if err != nil {
		return nil, err
	}

	rt, err := newBridgePublishedPortRuntimeWithDatapath(parent, d.portmappers, datapath, false)
	if err != nil {
		if created {
			_ = datapath.Close()
			d.datapath = nil
		}
		return nil, err
	}

	d.parents[parent] = &parentRuntime{
		parent:  parent,
		runtime: rt,
		refs:    1,
	}
	return rt, nil
}

func (d *driver) acquirePublishedPortDatapathLocked(ctx context.Context, parent string) (publishedPortDatapath, bool, error) {
	if d.datapath != nil {
		return d.datapath, false, nil
	}

	datapath, err := newPublishedPortDatapath(ctx, parent)
	if err != nil {
		return nil, false, err
	}
	if err := d.syncLocalEndpointsToPublishedDatapath(datapath); err != nil {
		_ = datapath.Close()
		return nil, false, err
	}
	d.datapath = datapath
	return datapath, true, nil
}

func (d *driver) upsertLocalEndpointDatapaths(ep *endpoint) error {
	d.configNetwork.Lock()
	defer d.configNetwork.Unlock()
	return d.upsertLocalEndpointDatapathsLocked(ep)
}

func (d *driver) upsertLocalEndpointDatapathsLocked(ep *endpoint) error {
	config, ok := localEndpointConfigForEndpoint(ep)
	if !ok {
		return nil
	}

	var errs []error
	if d.datapath != nil {
		errs = append(errs, d.datapath.UpsertLocalEndpoint(config))
	}
	d.mu.Lock()
	endpointDatapath := d.endpointDatapath
	d.mu.Unlock()
	if endpointDatapath != nil {
		errs = append(errs, endpointDatapath.UpsertLocalEndpoint(config))
	}
	return errors.Join(errs...)
}

func (d *driver) removeLocalEndpointDatapaths(ep *endpoint) error {
	d.configNetwork.Lock()
	defer d.configNetwork.Unlock()
	return d.removeLocalEndpointDatapathsLocked(ep)
}

func (d *driver) removeLocalEndpointDatapathsLocked(ep *endpoint) error {
	config, ok := localEndpointConfigForEndpoint(ep)
	if !ok {
		return nil
	}

	var errs []error
	if d.datapath != nil {
		errs = append(errs, d.datapath.RemoveLocalEndpoint(config))
	}
	d.mu.Lock()
	endpointDatapath := d.endpointDatapath
	d.mu.Unlock()
	if endpointDatapath != nil {
		errs = append(errs, endpointDatapath.RemoveLocalEndpoint(config))
	}
	return errors.Join(errs...)
}

func (d *driver) syncLocalEndpointsToPublishedDatapath(datapath publishedPortDatapath) error {
	var errs []error
	for _, n := range d.getNetworks() {
		n.mu.Lock()
		for _, ep := range n.endpoints {
			if config, ok := localEndpointConfigForEndpoint(ep); ok {
				errs = append(errs, datapath.UpsertLocalEndpoint(config))
			}
		}
		n.mu.Unlock()
	}
	return errors.Join(errs...)
}

func (d *driver) syncLocalEndpointsToEndpointDatapath(datapath endpointNetkitDatapath) error {
	var errs []error
	for _, n := range d.getNetworks() {
		n.mu.Lock()
		for _, ep := range n.endpoints {
			if config, ok := localEndpointConfigForEndpoint(ep); ok {
				errs = append(errs, datapath.UpsertLocalEndpoint(config))
			}
		}
		n.mu.Unlock()
	}
	return errors.Join(errs...)
}

func (d *driver) releaseParentRuntimeLocked(ctx context.Context, parent string) error {
	pr, ok := d.parents[parent]
	if !ok {
		return nil
	}

	pr.refs--
	if pr.refs > 0 {
		return nil
	}

	delete(d.parents, parent)
	err := pr.runtime.Close(ctx)
	if len(d.parents) != 0 || d.datapath == nil || len(d.datapathEndpoints) != 0 {
		return err
	}
	err = errors.Join(err, d.datapath.Close())
	d.datapath = nil
	d.sharedDatapathLinks = map[string]struct{}{}
	return err
}

type bridgePublishedPortRuntime struct {
	parent       string
	portmappers  *drvregistry.PortMappers
	datapath     publishedPortDatapath
	ownsDatapath bool

	mu        sync.Mutex
	endpoints map[string]*publishedEndpointState
}

type publishedEndpointState struct {
	hostIf   string
	ep4      *net.IPNet
	ep6      *net.IPNet
	bindings []portmapperapi.PortBinding
}

func newBridgePublishedPortRuntime(_ context.Context, parent string, _ bridge.Configuration, pms *drvregistry.PortMappers) (publishedPortRuntime, error) {
	if strings.TrimSpace(parent) == "" {
		return nil, fmt.Errorf("parent bridge name is empty")
	}
	if pms == nil {
		return nil, fmt.Errorf("port mapper registry is not initialized")
	}
	datapath, err := newPublishedPortDatapath(context.Background(), parent)
	if err != nil {
		return nil, err
	}
	return newBridgePublishedPortRuntimeWithDatapath(parent, pms, datapath, true)
}

func newBridgePublishedPortRuntimeWithDatapath(parent string, pms *drvregistry.PortMappers, datapath publishedPortDatapath, ownsDatapath bool) (publishedPortRuntime, error) {
	if strings.TrimSpace(parent) == "" {
		return nil, fmt.Errorf("parent bridge name is empty")
	}
	if pms == nil {
		return nil, fmt.Errorf("port mapper registry is not initialized")
	}
	if datapath == nil {
		return nil, fmt.Errorf("published port datapath is not initialized")
	}
	return &bridgePublishedPortRuntime{
		parent:       parent,
		portmappers:  pms,
		datapath:     datapath,
		ownsDatapath: ownsDatapath,
		endpoints:    map[string]*publishedEndpointState{},
	}, nil
}

func (r *bridgePublishedPortRuntime) AddEndpoint(_ context.Context, ep publishedEndpointConfig) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if err := r.datapath.AddPublishedEndpoint(ep); err != nil {
		return err
	}

	key := endpointStateKey(ep.Addr, ep.Addrv6)
	state := r.endpoints[key]
	if state == nil {
		state = &publishedEndpointState{}
		r.endpoints[key] = state
	}
	state.hostIf = ep.HostIf
	state.ep4 = cloneIPNet(ep.Addr)
	state.ep6 = cloneIPNet(ep.Addrv6)
	return nil
}

func (r *bridgePublishedPortRuntime) DelEndpoint(_ context.Context, ep publishedEndpointConfig) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.endpoints, endpointStateKey(ep.Addr, ep.Addrv6))
	return r.datapath.RemovePublishedEndpoint(ep)
}

func (r *bridgePublishedPortRuntime) ReconcilePortBindings(ctx context.Context, req publishedPortRequest) ([]portmapperapi.PortBinding, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := endpointStateKey(req.Addr, req.Addrv6)
	state := r.endpoints[key]
	if state == nil {
		state = &publishedEndpointState{
			ep4: cloneIPNet(req.Addr),
			ep6: cloneIPNet(req.Addrv6),
		}
		r.endpoints[key] = state
	}

	desiredReqs, err := r.expandPortBindings(req)
	if err != nil {
		return nil, err
	}

	var (
		keep      []portmapperapi.PortBinding
		toAdd     []portmapperapi.PortBindingReq
		toRelease []portmapperapi.PortBinding
	)
	for _, current := range req.Current {
		idx := slices.IndexFunc(desiredReqs, func(desired portmapperapi.PortBindingReq) bool {
			return bindingMatchesReq(current, desired)
		})
		if idx == -1 {
			toRelease = append(toRelease, current)
			continue
		}
		keep = append(keep, current)
		desiredReqs = slices.Delete(desiredReqs, idx, idx+1)
	}

	for i := range desiredReqs {
		if desiredReqs[i].HostPort != 0 {
			continue
		}
		if port, ok := inheritedHostPort(desiredReqs[i], req.Current); ok {
			desiredReqs[i].HostPort = port
			desiredReqs[i].HostPortEnd = port
		}
	}
	toAdd = append(toAdd, desiredReqs...)

	var added []portmapperapi.PortBinding
	if len(toAdd) != 0 {
		added, err = r.mapPortBindingReqs(ctx, toAdd)
		if err != nil {
			return nil, err
		}
		natAdded := natPortBindings(added)
		if len(natAdded) != 0 {
			if err := r.datapath.AddBindings(natAdded); err != nil {
				_ = r.unmapPortBindings(ctx, added)
				return nil, err
			}
		}
	}

	if len(toRelease) != 0 {
		natToRelease := natPortBindings(toRelease)
		if len(natToRelease) != 0 {
			if err := r.datapath.RemoveBindings(natToRelease); err != nil {
				if len(added) != 0 {
					if natAdded := natPortBindings(added); len(natAdded) != 0 {
						_ = r.datapath.RemoveBindings(natAdded)
					}
					_ = r.unmapPortBindings(ctx, added)
				}
				return nil, err
			}
		}
		if err := r.unmapPortBindings(ctx, toRelease); err != nil {
			if len(natToRelease) != 0 {
				_ = r.datapath.AddBindings(natToRelease)
			}
			if len(added) != 0 {
				if natAdded := natPortBindings(added); len(natAdded) != 0 {
					_ = r.datapath.RemoveBindings(natAdded)
				}
				_ = r.unmapPortBindings(ctx, added)
			}
			return nil, err
		}
	}

	state.bindings = append(clonePortBindings(keep), added...)
	return clonePortBindings(state.bindings), nil
}

func (r *bridgePublishedPortRuntime) ReleasePortBindings(ctx context.Context, bindings []portmapperapi.PortBinding) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	natBindings := natPortBindings(bindings)
	if len(natBindings) != 0 {
		if err := r.datapath.RemoveBindings(natBindings); err != nil {
			return err
		}
	}
	if err := r.unmapPortBindings(ctx, bindings); err != nil {
		if len(natBindings) != 0 {
			_ = r.datapath.AddBindings(natBindings)
		}
		return err
	}
	for _, state := range r.endpoints {
		state.bindings = slices.DeleteFunc(state.bindings, func(current portmapperapi.PortBinding) bool {
			return slices.ContainsFunc(bindings, func(released portmapperapi.PortBinding) bool {
				return current.Mapper == released.Mapper && current.Equal(released.PortBinding)
			})
		})
	}
	return nil
}

func (r *bridgePublishedPortRuntime) ClearConntrack(*net.IPNet, *net.IPNet, []portmapperapi.PortBinding) {
}

func (r *bridgePublishedPortRuntime) Close(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var all []portmapperapi.PortBinding
	for _, state := range r.endpoints {
		all = append(all, state.bindings...)
	}
	r.endpoints = map[string]*publishedEndpointState{}
	err := r.unmapPortBindings(ctx, all)
	if r.ownsDatapath {
		return errors.Join(err, r.datapath.Close())
	}
	return err
}

func toTypesPortBindings(bindings []portmapperapi.PortBinding) []types.PortBinding {
	res := make([]types.PortBinding, len(bindings))
	for i, pb := range bindings {
		res[i] = pb.PortBinding
	}
	return res
}

func (r *bridgePublishedPortRuntime) expandPortBindings(req publishedPortRequest) ([]portmapperapi.PortBindingReq, error) {
	var reqs []portmapperapi.PortBindingReq
	for _, binding := range req.PortBindings {
		if binding.HostPortEnd == 0 {
			binding.HostPortEnd = binding.HostPort
		}
		if req.DesiredMode.ipv4 || (req.DisableNATIPv4 && req.DesiredMode.routed) {
			b4, ok, err := configureNetkitPortBindingIPv4(binding, req.Addr, req.DisableNATIPv4)
			if err != nil {
				return nil, err
			}
			if ok {
				reqs = append(reqs, b4)
			}
		}
		if req.DesiredMode.ipv6 || (req.DisableNATIPv6 && req.DesiredMode.routed) {
			b6, ok, err := configureNetkitPortBindingIPv6(binding, req.Addrv6, req.DisableNATIPv6)
			if err != nil {
				return nil, err
			}
			if ok {
				reqs = append(reqs, b6)
			}
		}
	}
	slices.SortFunc(reqs, func(a, b portmapperapi.PortBindingReq) int {
		return a.Compare(b)
	})
	return reqs, nil
}

func configureNetkitPortBindingIPv4(bnd portmapperapi.PortBindingReq, ep4 *net.IPNet, disableNAT bool) (portmapperapi.PortBindingReq, bool, error) {
	if ep4 == nil {
		if len(bnd.HostIP) > 0 && bnd.HostIP.To4() != nil {
			return portmapperapi.PortBindingReq{}, false, types.InvalidParameterErrorf("netkit pure eBPF port mapping only supports same-family published ports")
		}
		return portmapperapi.PortBindingReq{}, false, nil
	}
	if len(bnd.HostIP) > 0 && bnd.HostIP.To4() == nil {
		return portmapperapi.PortBindingReq{}, false, nil
	}
	if len(bnd.HostIP) == 0 {
		bnd.HostIP = net.IPv4zero
	} else {
		bnd.HostIP = bnd.HostIP.To4()
	}
	if disableNAT {
		bnd.HostIP = net.IPv4zero
	}
	bnd.IP = ep4.IP.To4()
	bnd.Mapper = "nat"
	if disableNAT {
		bnd.Mapper = "routed"
	}
	return bnd, true, nil
}

func configureNetkitPortBindingIPv6(bnd portmapperapi.PortBindingReq, ep6 *net.IPNet, disableNAT bool) (portmapperapi.PortBindingReq, bool, error) {
	if ep6 == nil {
		if len(bnd.HostIP) > 0 && bnd.HostIP.To4() == nil {
			return portmapperapi.PortBindingReq{}, false, types.InvalidParameterErrorf("netkit pure eBPF port mapping only supports same-family published ports")
		}
		return portmapperapi.PortBindingReq{}, false, nil
	}
	if len(bnd.HostIP) > 0 && bnd.HostIP.To4() != nil {
		return portmapperapi.PortBindingReq{}, false, nil
	}
	if len(bnd.HostIP) == 0 {
		if !disableNAT && !isV6Listenable() {
			return portmapperapi.PortBindingReq{}, false, nil
		}
		bnd.HostIP = net.IPv6zero
	}
	if disableNAT {
		bnd.HostIP = net.IPv6zero
	}
	bnd.IP = cloneIP(ep6.IP)
	bnd.Mapper = "nat"
	if disableNAT {
		bnd.Mapper = "routed"
	}
	return bnd, true, nil
}

func bindingMatchesReq(current portmapperapi.PortBinding, desired portmapperapi.PortBindingReq) bool {
	return current.Proto == desired.Proto &&
		current.Port == desired.Port &&
		current.Mapper == desired.Mapper &&
		current.IP.Equal(desired.IP) &&
		current.HostIP.Equal(desired.HostIP)
}

func inheritedHostPort(desired portmapperapi.PortBindingReq, current []portmapperapi.PortBinding) (uint16, bool) {
	for _, binding := range current {
		if binding.Proto == desired.Proto && binding.Port == desired.Port && binding.Mapper == desired.Mapper {
			return binding.HostPort, true
		}
	}
	return 0, false
}

func (r *bridgePublishedPortRuntime) mapPortBindingReqs(ctx context.Context, reqs []portmapperapi.PortBindingReq) ([]portmapperapi.PortBinding, error) {
	if len(reqs) == 0 {
		return nil, nil
	}

	var all []portmapperapi.PortBinding
	rollbackMapped := func(cause error) error {
		if len(all) == 0 {
			return cause
		}
		return errors.Join(cause, r.unmapPortBindings(ctx, all))
	}

	var batch []portmapperapi.PortBindingReq
	for i, req := range reqs {
		batch = append(batch, req)
		if i < len(reqs)-1 && req.Mapper == reqs[i+1].Mapper && needSamePort(req, reqs[i+1]) {
			continue
		}

		pm, err := r.portmappers.Get(batch[0].Mapper)
		if err != nil {
			return nil, rollbackMapped(err)
		}
		mapped, err := pm.MapPorts(ctx, batch)
		if err != nil {
			return nil, rollbackMapped(err)
		}
		if err := validateNetkitMappedBindings(mapped); err != nil {
			return nil, rollbackMapped(errors.Join(err, pm.UnmapPorts(ctx, mapped)))
		}
		for i := range mapped {
			mapped[i].Mapper = batch[0].Mapper
		}
		all = append(all, mapped...)
		batch = batch[:0]
	}
	return all, nil
}

func validateNetkitMappedBindings(bindings []portmapperapi.PortBinding) error {
	for _, binding := range bindings {
		childHostIPMismatch := len(binding.ChildHostIP) > 0 && !binding.ChildHostIP.Equal(binding.HostIP)
		if binding.RootlesskitUnsupported || binding.PortDriverRemove != nil || childHostIPMismatch {
			return types.InvalidParameterErrorf("netkit pure eBPF port mapping does not support rootless port drivers: binding=%s rootlesskit_unsupported=%t port_driver_remove=%t host_ip=%s child_host_ip=%s",
				binding, binding.RootlesskitUnsupported, binding.PortDriverRemove != nil, binding.HostIP, binding.ChildHostIP)
		}
	}
	return nil
}

func (r *bridgePublishedPortRuntime) unmapPortBindings(ctx context.Context, bindings []portmapperapi.PortBinding) error {
	var errs []error
	for _, binding := range bindings {
		pm, err := r.portmappers.Get(binding.Mapper)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := pm.UnmapPorts(ctx, []portmapperapi.PortBinding{binding}); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func endpointStateKey(ep4, ep6 *net.IPNet) string {
	return fmt.Sprintf("%s|%s", ipNetString(ep4), ipNetString(ep6))
}

func ipNetString(nw *net.IPNet) string {
	if nw == nil {
		return ""
	}
	return nw.String()
}

func cloneIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	return slices.Clone(ip)
}

func cloneIPNet(nw *net.IPNet) *net.IPNet {
	if nw == nil {
		return nil
	}
	return &net.IPNet{
		IP:   cloneIP(nw.IP),
		Mask: slices.Clone(nw.Mask),
	}
}

func clonePortBindings(bindings []portmapperapi.PortBinding) []portmapperapi.PortBinding {
	res := make([]portmapperapi.PortBinding, len(bindings))
	copy(res, bindings)
	return res
}

func natPortBindings(bindings []portmapperapi.PortBinding) []portmapperapi.PortBinding {
	return slices.DeleteFunc(clonePortBindings(bindings), func(binding portmapperapi.PortBinding) bool {
		return binding.Mapper != "nat"
	})
}

func needSamePort(a, b portmapperapi.PortBindingReq) bool {
	return a.Port == b.Port &&
		a.Proto == b.Proto &&
		a.HostPort == b.HostPort &&
		a.HostPortEnd == b.HostPortEnd
}
