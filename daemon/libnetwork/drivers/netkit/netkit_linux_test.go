//go:build linux

package netkit

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/v2/daemon/libnetwork/driverapi"
	"github.com/moby/moby/v2/daemon/libnetwork/drivers/bridge"
	"github.com/moby/moby/v2/daemon/libnetwork/drvregistry"
	"github.com/moby/moby/v2/daemon/libnetwork/netlabel"
	"github.com/moby/moby/v2/daemon/libnetwork/netutils"
	"github.com/moby/moby/v2/daemon/libnetwork/portmapperapi"
	"github.com/moby/moby/v2/daemon/libnetwork/portmappers/routed"
	"github.com/moby/moby/v2/daemon/libnetwork/types"
	"github.com/moby/moby/v2/internal/sliceutil"
	"github.com/moby/moby/v2/internal/testutil/storeutils"
	"github.com/vishvananda/netlink"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

const testNetworkType = "netkit"

type driverTester struct {
	t *testing.T
	d *driver
}

func (dt *driverTester) RegisterDriver(name string, drv driverapi.Driver, capability driverapi.Capability) error {
	if name != testNetworkType {
		dt.t.Fatalf("expected driver register name %q, got %q", testNetworkType, name)
	}

	netkitDrv, ok := drv.(*driver)
	if !ok {
		dt.t.Fatalf("expected driver type %T, got %T", &driver{}, drv)
	}

	dt.d = netkitDrv
	return nil
}

func (dt *driverTester) RegisterNetworkAllocator(name string, _ driverapi.NetworkAllocator) error {
	dt.t.Fatalf("unexpected RegisterNetworkAllocator call for %q", name)
	return nil
}

func TestNetkitRegister(t *testing.T) {
	assert.NilError(t, Register(&driverTester{t: t}, storeutils.NewTempStore(t), nil, bridge.Configuration{}))
}

func TestNetkitType(t *testing.T) {
	dt := &driverTester{t: t}
	assert.NilError(t, Register(dt, storeutils.NewTempStore(t), nil, bridge.Configuration{}))
	assert.Check(t, is.Equal(dt.d.Type(), testNetworkType))
	assert.Check(t, dt.d.IsBuiltIn())
}

func TestParseNetworkOptionsRejectsLegacyParent(t *testing.T) {
	_, err := parseNetworkOptions("network-id", map[string]any{
		netlabel.GenericData: map[string]string{
			parentOpt: "br-test",
		},
	})
	assert.Check(t, err != nil)
	assert.Check(t, is.ErrorContains(err, "parent"))
}

func TestParseNetworkOptionsAcceptsL3NativeDefaults(t *testing.T) {
	cfg, err := parseNetworkOptions("network-id", map[string]any{
		netlabel.GenericData: map[string]string{},
	})
	assert.NilError(t, err)
	assert.Check(t, is.Equal(cfg.ID, "network-id"))
	assert.Check(t, !cfg.Internal)
}

func TestNewConfigFromLabelsParsesNATLabels(t *testing.T) {
	cfg, err := newConfigFromLabels(map[string]string{
		bridge.EnableIPMasquerade: "false",
		bridge.IPv4GatewayMode:    "routed",
		bridge.IPv6GatewayMode:    "nat",
		netlabel.HostIPv4:         "192.0.2.10",
		netlabel.HostIPv6:         "2001:db8::10",
	})

	assert.NilError(t, err)
	assert.Check(t, !cfg.EnableIPMasquerade)
	assert.Check(t, is.Equal(cfg.GwModeIPv4, gwModeRouted))
	assert.Check(t, is.Equal(cfg.GwModeIPv6, gwModeNAT))
	assert.Check(t, cfg.HostIPv4.Equal(net.ParseIP("192.0.2.10")))
	assert.Check(t, cfg.HostIPv6.Equal(net.ParseIP("2001:db8::10")))
}

func TestParseNetworkOptionsRejectsInvalidBridgeLabelValues(t *testing.T) {
	for _, tc := range []struct {
		name  string
		label string
		value string
	}{
		{
			name:  "invalid ipv4 gateway mode",
			label: bridge.IPv4GatewayMode,
			value: "bogus",
		},
		{
			name:  "invalid host ipv4",
			label: netlabel.HostIPv4,
			value: "2001:db8::10",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseNetworkOptions("network-id", map[string]any{
				netlabel.GenericData: map[string]string{
					tc.label: tc.value,
				},
			})
			assert.Check(t, err != nil)
			assert.Check(t, is.ErrorContains(err, "invalid"))
		})
	}
}

func TestEndpointOperInfoReturnsPublishedPorts(t *testing.T) {
	d := &driver{
		networks: map[string]*network{
			"n1": {
				id: "n1",
				endpoints: map[string]*endpoint{
					"ep1": {
						id: "ep1",
						extConnConfig: &connectivityConfiguration{
							ExposedPorts: []types.TransportPort{{Proto: types.TCP, Port: 80}},
						},
						portMapping: []portmapperapi.PortBinding{{
							PortBinding: types.PortBinding{
								Proto:    types.TCP,
								IP:       net.ParseIP("172.30.0.11"),
								Port:     80,
								HostIP:   net.IPv4zero,
								HostPort: 8080,
							},
							Mapper: "nat",
						}},
					},
				},
			},
		},
	}

	data, err := d.EndpointOperInfo("n1", "ep1")
	assert.NilError(t, err)

	pmd, ok := data[netlabel.PortMap]
	assert.Assert(t, ok)
	pbs, ok := pmd.([]types.PortBinding)
	assert.Assert(t, ok)
	assert.Assert(t, is.Len(pbs, 1))
	assert.Check(t, pbs[0].IP.Equal(net.ParseIP("172.30.0.11")))
	assert.Check(t, pbs[0].HostIP.Equal(net.IPv4zero))
	assert.Check(t, is.Equal(pbs[0].HostPort, uint16(8080)))

	exposed, ok := data[netlabel.ExposedPorts].([]types.TransportPort)
	assert.Assert(t, ok)
	assert.DeepEqual(t, exposed, []types.TransportPort{{Proto: types.TCP, Port: 80}})
}

func TestProbeKernelReturnsNotImplemented(t *testing.T) {
	d := &driver{
		probe: func() error {
			return errors.New("operation not supported")
		},
	}

	err := d.probeKernel()
	assert.Check(t, err != nil)
	assert.Check(t, cerrdefs.IsNotImplemented(err))
	assert.Check(t, is.ErrorContains(err, "Linux 6.7+"))
}

func TestProbeKernelCachesResult(t *testing.T) {
	calls := 0
	d := &driver{
		probe: func() error {
			calls++
			return nil
		},
	}

	assert.NilError(t, d.probeKernel())
	assert.NilError(t, d.probeKernel())
	assert.Check(t, is.Equal(calls, 1))
}

func TestProbeNetkitSupportAttachesPrograms(t *testing.T) {
	generateProbeIfaceNameSaved := generateProbeIfaceName
	addProbeLinkSaved := addProbeLink
	lookupProbeLinkSaved := lookupProbeLink
	deleteProbeLinkSaved := deleteProbeLink
	probeNetkitAttachSaved := probeNetkitAttach
	defer func() {
		generateProbeIfaceName = generateProbeIfaceNameSaved
		addProbeLink = addProbeLinkSaved
		lookupProbeLink = lookupProbeLinkSaved
		deleteProbeLink = deleteProbeLinkSaved
		probeNetkitAttach = probeNetkitAttachSaved
	}()

	var (
		addedLink       netlink.Link
		lookupNames     []string
		deletedLink     netlink.Link
		attachedIfindex int
	)
	ifaceNames := []string{"nkprobe0", "nkprobe1"}
	generateProbeIfaceName = func() (string, error) {
		name := ifaceNames[0]
		ifaceNames = ifaceNames[1:]
		return name, nil
	}
	addProbeLink = func(link netlink.Link) error {
		addedLink = link
		return nil
	}
	lookupProbeLink = func(name string) (netlink.Link, error) {
		lookupNames = append(lookupNames, name)
		return &netlink.Netkit{LinkAttrs: netlink.LinkAttrs{Name: name, Index: 42}}, nil
	}
	deleteProbeLink = func(link netlink.Link) error {
		deletedLink = link
		return nil
	}
	probeNetkitAttach = func(ifindex int) error {
		attachedIfindex = ifindex
		return nil
	}

	err := (&driver{}).probeNetkitSupport()
	assert.NilError(t, err)

	nk, ok := addedLink.(*netlink.Netkit)
	assert.Check(t, ok)
	assert.Check(t, is.Equal(nk.Attrs().Name, "nkprobe0"))
	assert.Check(t, is.Equal(nk.Mode, netlink.NETKIT_MODE_L3))
	assert.Check(t, is.Equal(nk.Policy, netlink.NETKIT_POLICY_BLACKHOLE))
	assert.Check(t, is.Equal(nk.PeerPolicy, netlink.NETKIT_POLICY_BLACKHOLE))
	assert.DeepEqual(t, lookupNames, []string{"nkprobe0"})
	assert.Check(t, is.Equal(attachedIfindex, 42))
	assert.Check(t, deletedLink != nil)
	assert.Check(t, is.Equal(deletedLink.Attrs().Name, "nkprobe0"))
}

func TestProbeNetkitSupportDeletesProbeLinkOnAttachFailure(t *testing.T) {
	generateProbeIfaceNameSaved := generateProbeIfaceName
	addProbeLinkSaved := addProbeLink
	lookupProbeLinkSaved := lookupProbeLink
	deleteProbeLinkSaved := deleteProbeLink
	probeNetkitAttachSaved := probeNetkitAttach
	defer func() {
		generateProbeIfaceName = generateProbeIfaceNameSaved
		addProbeLink = addProbeLinkSaved
		lookupProbeLink = lookupProbeLinkSaved
		deleteProbeLink = deleteProbeLinkSaved
		probeNetkitAttach = probeNetkitAttachSaved
	}()

	ifaceNames := []string{"nkprobe0", "nkprobe1"}
	generateProbeIfaceName = func() (string, error) {
		name := ifaceNames[0]
		ifaceNames = ifaceNames[1:]
		return name, nil
	}
	addProbeLink = func(netlink.Link) error { return nil }
	lookupProbeLink = func(name string) (netlink.Link, error) {
		return &netlink.Netkit{LinkAttrs: netlink.LinkAttrs{Name: name, Index: 42}}, nil
	}

	var deletedLink netlink.Link
	deleteProbeLink = func(link netlink.Link) error {
		deletedLink = link
		return nil
	}
	probeNetkitAttach = func(int) error {
		return errors.New("attach unsupported")
	}

	err := (&driver{}).probeNetkitSupport()
	assert.Check(t, err != nil)
	assert.Check(t, is.ErrorContains(err, "attach unsupported"))
	assert.Check(t, deletedLink != nil)
	assert.Check(t, is.Equal(deletedLink.Attrs().Name, "nkprobe0"))
}

func TestParseConnectivityOptionsRejectsSCTPPortBindings(t *testing.T) {
	_, err := parseConnectivityOptions(map[string]any{
		netlabel.PortMap: []types.PortBinding{{
			Proto: types.SCTP,
			Port:  80,
		}},
	})
	assert.Check(t, err != nil)
	assert.Check(t, is.ErrorContains(err, "unsupported"))
	assert.Check(t, is.ErrorContains(err, "sctp"))
}

type testInterface struct {
	mac                net.HardwareAddr
	addr               *net.IPNet
	addrv6             *net.IPNet
	netnsPath          string
	srcName            string
	dstPrefix          string
	dstName            string
	createdInContainer bool
}

type testEndpoint struct {
	iface                  *testInterface
	gw                     net.IP
	gw6                    net.IP
	routes                 []testRoute
	disableGatewayServices int
}

type testRoute struct {
	dst      *net.IPNet
	routeTyp types.RouteType
	nextHop  net.IP
}

func newTestEndpoint(nw *net.IPNet, ordinal byte) *testEndpoint {
	addr := types.GetIPNetCopy(nw)
	addr.IP[len(addr.IP)-1] = ordinal
	return &testEndpoint{iface: &testInterface{addr: addr}}
}

func (te *testEndpoint) Interface() *testInterface {
	return te.iface
}

func (i *testInterface) MacAddress() net.HardwareAddr {
	return i.mac
}

func (i *testInterface) Address() *net.IPNet {
	return i.addr
}

func (i *testInterface) AddressIPv6() *net.IPNet {
	return i.addrv6
}

func (i *testInterface) SetMacAddress(mac net.HardwareAddr) error {
	if i.mac != nil {
		return types.ForbiddenErrorf("endpoint interface MAC address present (%s). Cannot be modified with %s.", i.mac, mac)
	}
	if mac == nil {
		return types.InvalidParameterErrorf("tried to set nil MAC address to endpoint interface")
	}
	i.mac = slices.Clone(mac)
	return nil
}

func (i *testInterface) SetIPAddress(address *net.IPNet) error {
	if address.IP == nil {
		return types.InvalidParameterErrorf("tried to set nil IP address to endpoint interface")
	}
	if address.IP.To4() == nil {
		if i.addrv6 != nil {
			return types.ForbiddenErrorf("endpoint interface IPv6 present (%s). Cannot be modified with (%s).", i.addrv6, address)
		}
		i.addrv6 = types.GetIPNetCopy(address)
		return nil
	}
	if i.addr != nil {
		return types.ForbiddenErrorf("endpoint interface IPv4 present (%s). Cannot be modified with (%s).", i.addr, address)
	}
	i.addr = types.GetIPNetCopy(address)
	return nil
}

func (i *testInterface) NetnsPath() string {
	return i.netnsPath
}

func (i *testInterface) SetCreatedInContainer(cic bool) {
	i.createdInContainer = cic
}

func (i *testInterface) SetNames(srcName, dstPrefix, dstName string) error {
	i.srcName = srcName
	i.dstPrefix = dstPrefix
	i.dstName = dstName
	return nil
}

func (te *testEndpoint) InterfaceName() driverapi.InterfaceNameInfo {
	return te.iface
}

func (te *testEndpoint) SetGateway(gw net.IP) error {
	te.gw = gw
	return nil
}

func (te *testEndpoint) SetGatewayIPv6(gw6 net.IP) error {
	te.gw6 = gw6
	return nil
}

func (te *testEndpoint) AddStaticRoute(destination *net.IPNet, routeType types.RouteType, nextHop net.IP) error {
	var nextHopCopy net.IP
	if nextHop != nil {
		nextHopCopy = slices.Clone(nextHop)
	}
	te.routes = append(te.routes, testRoute{
		dst:      types.GetIPNetCopy(destination),
		routeTyp: routeType,
		nextHop:  nextHopCopy,
	})
	return nil
}

func (te *testEndpoint) AddTableEntry(tableName string, key string, value []byte) error {
	return nil
}

func (te *testEndpoint) DisableGatewayService() { te.disableGatewayServices++ }
func (te *testEndpoint) ForceGw4()              {}
func (te *testEndpoint) ForceGw6()              {}

type fakePublishedPortRuntime struct {
	addEndpointCalls int
	delEndpointCalls int
	addedEndpoints   []publishedEndpointConfig
	deletedEndpoints []publishedEndpointConfig
	reconcileCalls   []publishedPortRequest
	released         [][]portmapperapi.PortBinding
	clearConntrack   int
	closeCalls       int
}

func (f *fakePublishedPortRuntime) AddEndpoint(_ context.Context, ep publishedEndpointConfig) error {
	f.addEndpointCalls++
	f.addedEndpoints = append(f.addedEndpoints, ep)
	return nil
}

func (f *fakePublishedPortRuntime) DelEndpoint(_ context.Context, ep publishedEndpointConfig) error {
	f.delEndpointCalls++
	f.deletedEndpoints = append(f.deletedEndpoints, ep)
	return nil
}

func (f *fakePublishedPortRuntime) ReconcilePortBindings(_ context.Context, req publishedPortRequest) ([]portmapperapi.PortBinding, error) {
	f.reconcileCalls = append(f.reconcileCalls, req)
	res := make([]portmapperapi.PortBinding, len(req.PortBindings))
	for i, pb := range req.PortBindings {
		res[i] = portmapperapi.PortBinding{
			PortBinding: types.PortBinding{
				Proto:       pb.Proto,
				IP:          pb.IP,
				Port:        pb.Port,
				HostIP:      pb.HostIP,
				HostPort:    pb.HostPort,
				HostPortEnd: pb.HostPortEnd,
			},
			Mapper: pb.Mapper,
		}
		if res[i].HostPort == 0 {
			res[i].HostPort = 49152 + uint16(i)
			res[i].HostPortEnd = res[i].HostPort
		}
	}
	return res, nil
}

func (f *fakePublishedPortRuntime) ReleasePortBindings(_ context.Context, bindings []portmapperapi.PortBinding) error {
	f.released = append(f.released, slices.Clone(bindings))
	return nil
}

func (f *fakePublishedPortRuntime) ClearConntrack(_, _ *net.IPNet, _ []portmapperapi.PortBinding) {
	f.clearConntrack++
}

func (f *fakePublishedPortRuntime) Close(context.Context) error {
	f.closeCalls++
	return nil
}

func TestJoinUsesConnectedDefaultRoutes(t *testing.T) {
	store := storeutils.NewTempStore(t)
	epDatapath := &fakeEndpointNetkitDatapath{}
	d := &driver{
		store:    store,
		networks: map[string]*network{},
		parents:  map[string]*parentRuntime{},
		newEndpointDatapath: func(context.Context) (endpointNetkitDatapath, error) {
			return epDatapath, nil
		},
	}
	nw := &network{
		id:     "dummy",
		driver: d,
		config: &configuration{
			ID: "dummy",
			Ipv4Subnets: []*ipSubnet{{
				SubnetIP: "172.30.0.0/24",
				GwIP:     "172.30.0.1/24",
			}},
			Ipv6Subnets: []*ipSubnet{{
				SubnetIP: "fd00::/64",
				GwIP:     "fd00::1/64",
			}},
		},
		endpoints: map[string]*endpoint{},
	}
	d.networks[nw.id] = nw

	createNetkitSaved := createNetkitFn
	generateIfaceNameSaved := generateIfaceName
	hostLinkByNameSaved := hostLinkByName
	replaceHostRouteSaved := replaceHostRoute
	createNetkitFn = func(hostIfName, containerIfName, parent, sboxKey string, mac net.HardwareAddr, enableBigTCP bool) error {
		assert.Check(t, is.Equal(parent, ""))
		assert.Check(t, mac == nil)
		return nil
	}
	ifaceNames := []string{"nkhost0", "nkcont0"}
	generateIfaceName = func() (string, error) {
		name := ifaceNames[0]
		ifaceNames = ifaceNames[1:]
		return name, nil
	}
	hostLinkByName = func(name string) (netlink.Link, error) {
		return &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: name, Index: 42}}, nil
	}
	replaceHostRoute = func(*netlink.Route) error { return nil }
	defer func() {
		createNetkitFn = createNetkitSaved
		generateIfaceName = generateIfaceNameSaved
		hostLinkByName = hostLinkByNameSaved
		replaceHostRoute = replaceHostRouteSaved
	}()

	te := newTestEndpoint(mustParseCIDR(t, "172.30.0.0/24"), 11)
	_, ep6, err := net.ParseCIDR("fd00::11/64")
	assert.NilError(t, err)
	ep6.IP = net.ParseIP("fd00::11")
	assert.NilError(t, te.Interface().SetIPAddress(ep6))
	assert.NilError(t, d.CreateEndpoint(context.Background(), "dummy", "ep1", te.Interface(), nil))

	assert.NilError(t, d.Join(context.Background(), "dummy", "ep1", "/netns/fake", te, nil, nil))
	assert.Check(t, te.gw == nil)
	assert.Check(t, te.gw6 == nil)
	assert.Check(t, is.Equal(te.disableGatewayServices, 1))
	assert.Check(t, is.Len(te.routes, 2))
	assert.Check(t, te.routes[0].dst.IP.Equal(net.IPv4zero))
	assert.Check(t, is.Equal(te.routes[0].routeTyp, types.CONNECTED))
	assert.Check(t, te.routes[0].nextHop == nil)
	assert.Check(t, te.routes[1].dst.IP.Equal(net.IPv6zero))
	assert.Check(t, is.Equal(te.routes[1].routeTyp, types.CONNECTED))
	assert.Check(t, te.routes[1].nextHop == nil)
	assert.DeepEqual(t, epDatapath.attached, []string{"nkhost0"})
}

func TestCreateEndpointDoesNotAssignMACInL3Mode(t *testing.T) {
	store := storeutils.NewTempStore(t)
	d := &driver{
		store:    store,
		networks: map[string]*network{},
		parents:  map[string]*parentRuntime{},
	}
	d.networks["dummy"] = &network{
		id:        "dummy",
		driver:    d,
		config:    &configuration{ID: "dummy"},
		endpoints: map[string]*endpoint{},
	}

	te := newTestEndpoint(mustParseCIDR(t, "172.30.0.0/24"), 11)
	assert.NilError(t, d.CreateEndpoint(context.Background(), "dummy", "ep1", te.Interface(), nil))
	assert.Check(t, te.Interface().MacAddress() == nil)

	ep, err := d.networks["dummy"].endpoint("ep1")
	assert.NilError(t, err)
	assert.Check(t, ep.mac == nil)
}

func TestCreateEndpointRejectsCustomMACInL3Mode(t *testing.T) {
	store := storeutils.NewTempStore(t)
	d := &driver{
		store:    store,
		networks: map[string]*network{},
		parents:  map[string]*parentRuntime{},
	}
	d.networks["dummy"] = &network{
		id:        "dummy",
		driver:    d,
		config:    &configuration{ID: "dummy"},
		endpoints: map[string]*endpoint{},
	}

	te := newTestEndpoint(mustParseCIDR(t, "172.30.0.0/24"), 11)
	te.iface.mac = netutils.MustParseMAC("02:42:ac:11:00:0b")

	err := d.CreateEndpoint(context.Background(), "dummy", "ep1", te.Interface(), nil)
	assert.Check(t, err != nil)
	assert.Check(t, is.ErrorContains(err, "support custom mac"))
}

func TestNetkitBigTCPDefaultsEnabled(t *testing.T) {
	config := defaultConfiguration()

	assert.Check(t, config.EnableBigTCP)
}

func TestNetkitBigTCPLabelParsesBool(t *testing.T) {
	config, err := newConfigFromLabels(map[string]string{
		bigTCPOpt: "false",
	})
	assert.NilError(t, err)
	assert.Check(t, !config.EnableBigTCP)

	config, err = newConfigFromLabels(map[string]string{
		bigTCPOpt: "true",
	})
	assert.NilError(t, err)
	assert.Check(t, config.EnableBigTCP)
}

func TestNetkitBigTCPLabelRejectsInvalidValue(t *testing.T) {
	_, err := newConfigFromLabels(map[string]string{
		bigTCPOpt: "bogus",
	})

	assert.Check(t, err != nil)
	assert.Check(t, is.ErrorContains(err, bigTCPOpt))
}

type fakeBigTCPConfigurer struct {
	calls []string
}

func (f *fakeBigTCPConfigurer) LinkSetGSOMaxSize(link netlink.Link, maxSize int) error {
	f.calls = append(f.calls, fmt.Sprintf("gso:%s:%d", link.Attrs().Name, maxSize))
	return nil
}

func (f *fakeBigTCPConfigurer) LinkSetGROMaxSize(link netlink.Link, maxSize int) error {
	f.calls = append(f.calls, fmt.Sprintf("gro:%s:%d", link.Attrs().Name, maxSize))
	return nil
}

func (f *fakeBigTCPConfigurer) LinkSetGSOIPv4MaxSize(link netlink.Link, maxSize int) error {
	f.calls = append(f.calls, fmt.Sprintf("gso4:%s:%d", link.Attrs().Name, maxSize))
	return nil
}

func (f *fakeBigTCPConfigurer) LinkSetGROIPv4MaxSize(link netlink.Link, maxSize int) error {
	f.calls = append(f.calls, fmt.Sprintf("gro4:%s:%d", link.Attrs().Name, maxSize))
	return nil
}

func TestSetLinkBigTCPMaxSizesConfiguresIPv4AndIPv6(t *testing.T) {
	fake := &fakeBigTCPConfigurer{}
	link := &netlink.Netkit{LinkAttrs: netlink.LinkAttrs{Name: "nk123", Index: 42}}

	assert.NilError(t, setLinkBigTCPMaxSizes(fake, link))

	assert.DeepEqual(t, fake.calls, []string{
		"gro:nk123:196608",
		"gso:nk123:196608",
		"gro4:nk123:196608",
		"gso4:nk123:196608",
	})
}

func TestJoinProgramsHostRoutesForEndpoint(t *testing.T) {
	store := storeutils.NewTempStore(t)
	epDatapath := &fakeEndpointNetkitDatapath{}
	d := &driver{
		store:    store,
		networks: map[string]*network{},
		parents:  map[string]*parentRuntime{},
		newEndpointDatapath: func(context.Context) (endpointNetkitDatapath, error) {
			return epDatapath, nil
		},
	}
	nw := &network{
		id:        "dummy",
		driver:    d,
		config:    &configuration{ID: "dummy", EnableBigTCP: true},
		endpoints: map[string]*endpoint{},
	}
	d.networks[nw.id] = nw

	createNetkitSaved := createNetkitFn
	generateIfaceNameSaved := generateIfaceName
	hostLinkByNameSaved := hostLinkByName
	replaceHostRouteSaved := replaceHostRoute
	var replaced []netlink.Route
	createNetkitFn = func(hostIfName, containerIfName, parent, sboxKey string, mac net.HardwareAddr, enableBigTCP bool) error {
		assert.Check(t, enableBigTCP)
		return nil
	}
	ifaceNames := []string{"nkhost0", "nkcont0"}
	generateIfaceName = func() (string, error) {
		name := ifaceNames[0]
		ifaceNames = ifaceNames[1:]
		return name, nil
	}
	hostLinkByName = func(name string) (netlink.Link, error) {
		assert.Check(t, is.Equal(name, "nkhost0"))
		return &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: name, Index: 42}}, nil
	}
	replaceHostRoute = func(route *netlink.Route) error {
		replaced = append(replaced, *route)
		return nil
	}
	defer func() {
		createNetkitFn = createNetkitSaved
		generateIfaceName = generateIfaceNameSaved
		hostLinkByName = hostLinkByNameSaved
		replaceHostRoute = replaceHostRouteSaved
	}()

	te := newTestEndpoint(mustParseCIDR(t, "172.30.0.0/24"), 11)
	_, ep6, err := net.ParseCIDR("fd00::11/64")
	assert.NilError(t, err)
	ep6.IP = net.ParseIP("fd00::11")
	assert.NilError(t, te.Interface().SetIPAddress(ep6))
	assert.NilError(t, d.CreateEndpoint(context.Background(), "dummy", "ep1", te.Interface(), nil))

	assert.NilError(t, d.Join(context.Background(), "dummy", "ep1", "/netns/fake", te, nil, nil))
	assert.Check(t, is.Len(replaced, 2))
	assert.Check(t, is.Equal(replaced[0].LinkIndex, 42))
	assert.Check(t, is.Equal(replaced[0].Scope, netlink.SCOPE_LINK))
	assert.Check(t, is.Equal(replaced[1].LinkIndex, 42))
	assert.Check(t, is.Equal(replaced[1].Scope, netlink.SCOPE_LINK))
}

func TestJoinProgramsLocalEndpointState(t *testing.T) {
	store := storeutils.NewTempStore(t)
	epDatapath := &fakeEndpointNetkitDatapath{}
	d := &driver{
		store:    store,
		networks: map[string]*network{},
		parents:  map[string]*parentRuntime{},
		newEndpointDatapath: func(context.Context) (endpointNetkitDatapath, error) {
			return epDatapath, nil
		},
	}
	nw := &network{
		id:        "dummy",
		driver:    d,
		config:    &configuration{ID: "dummy"},
		endpoints: map[string]*endpoint{},
	}
	d.networks[nw.id] = nw

	createNetkitSaved := createNetkitFn
	generateIfaceNameSaved := generateIfaceName
	hostLinkByNameSaved := hostLinkByName
	replaceHostRouteSaved := replaceHostRoute
	createNetkitFn = func(hostIfName, containerIfName, parent, sboxKey string, mac net.HardwareAddr, enableBigTCP bool) error {
		return nil
	}
	ifaceNames := []string{"nkhost0", "nkcont0"}
	generateIfaceName = func() (string, error) {
		name := ifaceNames[0]
		ifaceNames = ifaceNames[1:]
		return name, nil
	}
	hostLinkByName = func(name string) (netlink.Link, error) {
		assert.Check(t, is.Equal(name, "nkhost0"))
		return &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: name, Index: 42}}, nil
	}
	replaceHostRoute = func(*netlink.Route) error { return nil }
	defer func() {
		createNetkitFn = createNetkitSaved
		generateIfaceName = generateIfaceNameSaved
		hostLinkByName = hostLinkByNameSaved
		replaceHostRoute = replaceHostRouteSaved
	}()

	te := newTestEndpoint(mustParseCIDR(t, "172.30.0.0/24"), 11)
	_, ep6, err := net.ParseCIDR("fd00::11/64")
	assert.NilError(t, err)
	ep6.IP = net.ParseIP("fd00::11")
	assert.NilError(t, te.Interface().SetIPAddress(ep6))
	assert.NilError(t, d.CreateEndpoint(context.Background(), "dummy", "ep1", te.Interface(), nil))

	assert.NilError(t, d.Join(context.Background(), "dummy", "ep1", "/netns/fake", te, nil, nil))
	assert.Check(t, len(epDatapath.upsertedLocalEndpoints) > 0)
	got := epDatapath.upsertedLocalEndpoints[len(epDatapath.upsertedLocalEndpoints)-1]
	assert.Check(t, is.Equal(got.NetworkID, "dummy"))
	assert.Check(t, got.NetworkKey != [16]byte{})
	assert.Check(t, is.Equal(got.HostIf, "nkhost0"))
	assert.Check(t, is.Equal(got.Addr.IP.String(), "172.30.0.11"))
	assert.Check(t, is.Equal(got.Addrv6.IP.String(), "fd00::11"))
}

func TestJoinProgramsEgressMasqueradeState(t *testing.T) {
	store := storeutils.NewTempStore(t)
	epDatapath := &fakeEndpointNetkitDatapath{}
	datapath := &fakePublishedPortDatapath{}
	d := &driver{
		store:    store,
		networks: map[string]*network{},
		parents:  map[string]*parentRuntime{},
		newEndpointDatapath: func(context.Context) (endpointNetkitDatapath, error) {
			return epDatapath, nil
		},
	}
	nw := &network{
		id:     "dummy",
		driver: d,
		config: &configuration{
			ID:                 "dummy",
			EnableIPMasquerade: true,
			GwModeIPv4:         gwModeNAT,
		},
		endpoints: map[string]*endpoint{},
	}
	d.networks[nw.id] = nw

	createNetkitSaved := createNetkitFn
	generateIfaceNameSaved := generateIfaceName
	hostLinkByNameSaved := hostLinkByName
	replaceHostRouteSaved := replaceHostRoute
	newPublishedPortDatapathSaved := newPublishedPortDatapath
	createNetkitFn = func(hostIfName, containerIfName, parent, sboxKey string, mac net.HardwareAddr, enableBigTCP bool) error {
		return nil
	}
	ifaceNames := []string{"nkhost0", "nkcont0"}
	generateIfaceName = func() (string, error) {
		name := ifaceNames[0]
		ifaceNames = ifaceNames[1:]
		return name, nil
	}
	hostLinkByName = func(name string) (netlink.Link, error) {
		return &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: name, Index: 42}}, nil
	}
	replaceHostRoute = func(*netlink.Route) error { return nil }
	newPublishedPortDatapath = func(context.Context, string) (publishedPortDatapath, error) {
		return datapath, nil
	}
	defer func() {
		createNetkitFn = createNetkitSaved
		generateIfaceName = generateIfaceNameSaved
		hostLinkByName = hostLinkByNameSaved
		replaceHostRoute = replaceHostRouteSaved
		newPublishedPortDatapath = newPublishedPortDatapathSaved
	}()

	te := newTestEndpoint(mustParseCIDR(t, "172.30.0.0/24"), 11)
	assert.NilError(t, d.CreateEndpoint(context.Background(), "dummy", "ep1", te.Interface(), nil))

	assert.NilError(t, d.Join(context.Background(), "dummy", "ep1", "/netns/fake", te, nil, nil))
	assert.Check(t, is.Len(datapath.upsertedEndpoints, 1))
	assert.Check(t, is.Equal(datapath.upsertedEndpoints[0].HostIf, "nkhost0"))
	assert.Check(t, is.Equal(datapath.upsertedEndpoints[0].Addr.IP.String(), "172.30.0.11"))
	assert.Check(t, datapath.upsertedEndpoints[0].MasqueradeIPv4)
	assert.Check(t, datapath.upsertedEndpoints[0].HostIPv4 == nil)
}

func TestEgressEndpointConfigForNetworkUsesConfiguredHostIP(t *testing.T) {
	cfg, ok := egressEndpointConfigForNetwork(&configuration{
		EnableIPMasquerade: true,
		GwModeIPv4:         gwModeNAT,
		HostIPv4:           net.ParseIP("192.0.2.10"),
	}, &endpoint{
		addr: mustParseCIDR(t, "172.30.0.11/24"),
	})
	assert.Check(t, ok)
	assert.Check(t, cfg.HostIPv4.Equal(net.ParseIP("192.0.2.10")))
	assert.Check(t, !cfg.MasqueradeIPv4)
}

func TestEgressEndpointConfigForNetworkSkipsRoutedFamilies(t *testing.T) {
	cfg, ok := egressEndpointConfigForNetwork(&configuration{
		EnableIPMasquerade: true,
		GwModeIPv4:         gwModeRouted,
		GwModeIPv6:         gwModeNAT,
	}, &endpoint{
		addr:   mustParseCIDR(t, "172.30.0.11/24"),
		addrv6: mustParseCIDR(t, "fd00::11/64"),
	})
	assert.Check(t, ok)
	assert.Check(t, cfg.Addr == nil)
	assert.Check(t, cfg.MasqueradeIPv6)
}

func TestLeaveRemovesEgressMasqueradeState(t *testing.T) {
	store := storeutils.NewTempStore(t)
	epDatapath := &fakeEndpointNetkitDatapath{}
	datapath := &fakePublishedPortDatapath{}
	d := &driver{
		store:    store,
		networks: map[string]*network{},
		parents:  map[string]*parentRuntime{},
		newEndpointDatapath: func(context.Context) (endpointNetkitDatapath, error) {
			return epDatapath, nil
		},
	}
	nw := &network{
		id:     "dummy",
		driver: d,
		config: &configuration{
			ID:                 "dummy",
			EnableIPMasquerade: true,
			GwModeIPv4:         gwModeNAT,
		},
		endpoints: map[string]*endpoint{},
	}
	d.networks[nw.id] = nw

	createNetkitSaved := createNetkitFn
	generateIfaceNameSaved := generateIfaceName
	hostLinkByNameSaved := hostLinkByName
	replaceHostRouteSaved := replaceHostRoute
	deleteHostRouteSaved := deleteHostRoute
	newPublishedPortDatapathSaved := newPublishedPortDatapath
	createNetkitFn = func(hostIfName, containerIfName, parent, sboxKey string, mac net.HardwareAddr, enableBigTCP bool) error {
		return nil
	}
	ifaceNames := []string{"nkhost0", "nkcont0"}
	generateIfaceName = func() (string, error) {
		name := ifaceNames[0]
		ifaceNames = ifaceNames[1:]
		return name, nil
	}
	hostLinkByName = func(name string) (netlink.Link, error) {
		return &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: name, Index: 42}}, nil
	}
	replaceHostRoute = func(*netlink.Route) error { return nil }
	deleteHostRoute = func(*netlink.Route) error { return nil }
	newPublishedPortDatapath = func(context.Context, string) (publishedPortDatapath, error) {
		return datapath, nil
	}
	defer func() {
		createNetkitFn = createNetkitSaved
		generateIfaceName = generateIfaceNameSaved
		hostLinkByName = hostLinkByNameSaved
		replaceHostRoute = replaceHostRouteSaved
		deleteHostRoute = deleteHostRouteSaved
		newPublishedPortDatapath = newPublishedPortDatapathSaved
	}()

	te := newTestEndpoint(mustParseCIDR(t, "172.30.0.0/24"), 11)
	assert.NilError(t, d.CreateEndpoint(context.Background(), "dummy", "ep1", te.Interface(), nil))
	assert.NilError(t, d.Join(context.Background(), "dummy", "ep1", "/netns/fake", te, nil, nil))
	assert.DeepEqual(t, datapath.attached, []string{"nkhost0"})
	assert.DeepEqual(t, epDatapath.attached, []string(nil))

	assert.NilError(t, d.Leave("dummy", "ep1"))
	assert.Check(t, is.Len(datapath.removedEndpoints, 1))
	assert.Check(t, is.Equal(datapath.removedEndpoints[0].Addr.IP.String(), "172.30.0.11"))
	assert.Check(t, is.Equal(datapath.closeCalls, 1))
}

func TestAttachEndpointDatapathUsesStandaloneForUnreferencedEndpoint(t *testing.T) {
	sharedDatapath := &fakePublishedPortDatapath{}
	standaloneDatapath := &fakeEndpointNetkitDatapath{}
	d := &driver{
		datapath:         sharedDatapath,
		endpointDatapath: standaloneDatapath,
		datapathEndpoints: map[string]struct{}{
			"dummy/referenced": {},
		},
	}
	ep := &endpoint{
		id:     "unreferenced",
		nid:    "dummy",
		hostIf: "nkstandalone0",
	}

	assert.NilError(t, d.attachEndpointDatapath(context.Background(), ep))
	assert.DeepEqual(t, standaloneDatapath.attached, []string{"nkstandalone0"})
	assert.DeepEqual(t, sharedDatapath.attached, []string(nil))
}

func TestJoinAndProgramExternalConnectivityPublishesPorts(t *testing.T) {
	store := storeutils.NewTempStore(t)
	runtime := &fakePublishedPortRuntime{}
	epDatapath := &fakeEndpointNetkitDatapath{}
	d := &driver{
		store:    store,
		networks: map[string]*network{},
		parents:  map[string]*parentRuntime{},
		newEndpointDatapath: func(context.Context) (endpointNetkitDatapath, error) {
			return epDatapath, nil
		},
		newPortRuntime: func(context.Context, string) (publishedPortRuntime, error) {
			return runtime, nil
		},
	}
	nw := &network{
		id:     "dummy",
		driver: d,
		config: &configuration{
			ID:     "dummy",
			Parent: "br-test",
			Ipv4Subnets: []*ipSubnet{{
				SubnetIP: "172.30.0.0/24",
				GwIP:     "172.30.0.1/24",
			}},
		},
		endpoints: map[string]*endpoint{},
	}
	d.networks[nw.id] = nw

	createNetkitSaved := createNetkitFn
	generateIfaceNameSaved := generateIfaceName
	hostLinkByNameSaved := hostLinkByName
	replaceHostRouteSaved := replaceHostRoute
	deleteHostRouteSaved := deleteHostRoute
	createNetkitFn = func(hostIfName, containerIfName, parent, sboxKey string, mac net.HardwareAddr, enableBigTCP bool) error {
		return nil
	}
	ifaceNames := []string{"nkhost0", "nkcont0"}
	generateIfaceName = func() (string, error) {
		name := ifaceNames[0]
		ifaceNames = ifaceNames[1:]
		return name, nil
	}
	hostLinkByName = func(name string) (netlink.Link, error) {
		return &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: name, Index: 24}}, nil
	}
	replaceHostRoute = func(*netlink.Route) error { return nil }
	deleteHostRoute = func(*netlink.Route) error { return nil }
	defer func() {
		createNetkitFn = createNetkitSaved
		generateIfaceName = generateIfaceNameSaved
		hostLinkByName = hostLinkByNameSaved
		replaceHostRoute = replaceHostRouteSaved
		deleteHostRoute = deleteHostRouteSaved
	}()

	te := newTestEndpoint(mustParseCIDR(t, "172.30.0.0/24"), 11)
	assert.NilError(t, d.CreateEndpoint(context.Background(), "dummy", "ep1", te.Interface(), nil))

	sbOptions := map[string]any{
		netlabel.PortMap: []types.PortBinding{{
			Proto:    types.TCP,
			Port:     80,
			HostPort: 8080,
		}},
	}
	assert.NilError(t, d.Join(context.Background(), "dummy", "ep1", "/netns/fake", te, nil, sbOptions))

	ep, err := nw.endpoint("ep1")
	assert.NilError(t, err)
	assert.Check(t, ep.extConnConfig != nil)
	assert.Check(t, is.Equal(len(ep.extConnConfig.PortBindings), 1))
	assert.Check(t, is.Equal(ep.publishedParent, "dummy"))
	assert.Check(t, is.Equal(runtime.addEndpointCalls, 1))
	assert.Check(t, is.Equal(runtime.addedEndpoints[0].HostIf, "nkhost0"))

	assert.NilError(t, d.ProgramExternalConnectivity(context.Background(), "dummy", "ep1", "ep1", ""))
	assert.Check(t, is.Equal(len(runtime.reconcileCalls), 1))
	assert.Check(t, runtime.reconcileCalls[0].DesiredMode.ipv4)
	assert.Check(t, !runtime.reconcileCalls[0].DesiredMode.ipv6)
	assert.Check(t, is.Equal(len(ep.portMapping), 1))
	assert.Check(t, is.Equal(ep.portMapping[0].HostPort, uint16(8080)))
	assert.Check(t, is.Equal(runtime.clearConntrack, 1))

	assert.NilError(t, d.Leave("dummy", "ep1"))
	assert.Check(t, is.Equal(len(runtime.released), 1))
	assert.Check(t, is.Equal(runtime.delEndpointCalls, 1))
	assert.Check(t, is.Equal(runtime.deletedEndpoints[0].HostIf, "nkhost0"))
	assert.Check(t, is.Equal(runtime.closeCalls, 1))
}

func TestJoinRejectsCrossFamilyPublishedPortBinding(t *testing.T) {
	store := storeutils.NewTempStore(t)
	runtime := &fakePublishedPortRuntime{}
	epDatapath := &fakeEndpointNetkitDatapath{}
	d := &driver{
		store:    store,
		networks: map[string]*network{},
		parents:  map[string]*parentRuntime{},
		newEndpointDatapath: func(context.Context) (endpointNetkitDatapath, error) {
			return epDatapath, nil
		},
		newPortRuntime: func(context.Context, string) (publishedPortRuntime, error) {
			return runtime, nil
		},
	}
	nw := &network{
		id:     "dummy",
		driver: d,
		config: &configuration{
			ID:     "dummy",
			Parent: "br-test",
			Ipv4Subnets: []*ipSubnet{{
				SubnetIP: "172.30.0.0/24",
				GwIP:     "172.30.0.1/24",
			}},
		},
		endpoints: map[string]*endpoint{},
	}
	d.networks[nw.id] = nw

	createNetkitSaved := createNetkitFn
	generateIfaceNameSaved := generateIfaceName
	createNetkitFn = func(hostIfName, containerIfName, parent, sboxKey string, mac net.HardwareAddr, enableBigTCP bool) error {
		return nil
	}
	ifaceNames := []string{"nkhostx", "nkcontx"}
	generateIfaceName = func() (string, error) {
		name := ifaceNames[0]
		ifaceNames = ifaceNames[1:]
		return name, nil
	}
	defer func() {
		createNetkitFn = createNetkitSaved
		generateIfaceName = generateIfaceNameSaved
	}()

	te := newTestEndpoint(mustParseCIDR(t, "172.30.0.0/24"), 22)
	assert.NilError(t, d.CreateEndpoint(context.Background(), "dummy", "ep1", te.Interface(), nil))

	err := d.Join(context.Background(), "dummy", "ep1", "/netns/fake", te, nil, map[string]any{
		netlabel.PortMap: []types.PortBinding{{
			Proto:    types.TCP,
			Port:     80,
			HostIP:   net.ParseIP("::1"),
			HostPort: 8080,
		}},
	})
	assert.Check(t, err != nil)
	assert.Check(t, is.ErrorContains(err, "same-family"))
}

func TestPublishedPortRuntimeIsScopedPerNetwork(t *testing.T) {
	store := storeutils.NewTempStore(t)
	runtime := &fakePublishedPortRuntime{}
	epDatapath := &fakeEndpointNetkitDatapath{}
	creations := 0
	d := &driver{
		store:    store,
		networks: map[string]*network{},
		parents:  map[string]*parentRuntime{},
		newEndpointDatapath: func(context.Context) (endpointNetkitDatapath, error) {
			return epDatapath, nil
		},
		newPortRuntime: func(context.Context, string) (publishedPortRuntime, error) {
			creations++
			return runtime, nil
		},
	}

	for _, nid := range []string{"n1", "n2"} {
		d.networks[nid] = &network{
			id:     nid,
			driver: d,
			config: &configuration{
				ID: nid,
				Ipv4Subnets: []*ipSubnet{{
					SubnetIP: "172.31.0.0/24",
					GwIP:     "172.31.0.1/24",
				}},
			},
			endpoints: map[string]*endpoint{},
		}
	}

	createNetkitSaved := createNetkitFn
	generateIfaceNameSaved := generateIfaceName
	hostLinkByNameSaved := hostLinkByName
	replaceHostRouteSaved := replaceHostRoute
	deleteHostRouteSaved := deleteHostRoute
	createNetkitFn = func(hostIfName, containerIfName, parent, sboxKey string, mac net.HardwareAddr, enableBigTCP bool) error {
		return nil
	}
	ifaceIdx := 0
	generateIfaceName = func() (string, error) {
		name := []string{"nkhost1", "nkcont1", "nkhost2", "nkcont2"}[ifaceIdx]
		ifaceIdx++
		return name, nil
	}
	hostLinkByName = func(name string) (netlink.Link, error) {
		return &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: name, Index: 64}}, nil
	}
	replaceHostRoute = func(*netlink.Route) error { return nil }
	deleteHostRoute = func(*netlink.Route) error { return nil }
	defer func() {
		createNetkitFn = createNetkitSaved
		generateIfaceName = generateIfaceNameSaved
		hostLinkByName = hostLinkByNameSaved
		replaceHostRoute = replaceHostRouteSaved
		deleteHostRoute = deleteHostRouteSaved
	}()

	portMap := map[string]any{
		netlabel.PortMap: []types.PortBinding{{
			Proto:    types.TCP,
			Port:     80,
			HostPort: 8080,
		}},
	}

	for idx, nid := range []string{"n1", "n2"} {
		te := newTestEndpoint(mustParseCIDR(t, "172.31.0.0/24"), byte(11+idx))
		eid := "ep" + nid
		assert.NilError(t, d.CreateEndpoint(context.Background(), nid, eid, te.Interface(), nil))
		assert.NilError(t, d.Join(context.Background(), nid, eid, "/netns/fake", te, nil, portMap))
		assert.NilError(t, d.ProgramExternalConnectivity(context.Background(), nid, eid, eid, ""))
	}

	assert.Check(t, is.Equal(creations, 2))

	assert.NilError(t, d.Leave("n1", "epn1"))
	assert.Check(t, is.Equal(runtime.closeCalls, 1))
	assert.NilError(t, d.Leave("n2", "epn2"))
	assert.Check(t, is.Equal(runtime.closeCalls, 2))
}

func TestLeaveRemovesHostRoutesWithoutPublishedPorts(t *testing.T) {
	store := storeutils.NewTempStore(t)
	epDatapath := &fakeEndpointNetkitDatapath{}
	d := &driver{
		store:            store,
		networks:         map[string]*network{},
		parents:          map[string]*parentRuntime{},
		endpointDatapath: epDatapath,
	}
	nw := &network{
		id:     "dummy",
		driver: d,
		config: &configuration{ID: "dummy"},
		endpoints: map[string]*endpoint{
			"ep1": {
				id:     "ep1",
				nid:    "dummy",
				hostIf: "nkhost0",
				addr:   mustParseCIDR(t, "172.31.0.11/24"),
			},
		},
	}
	d.networks[nw.id] = nw

	hostLinkByNameSaved := hostLinkByName
	deleteHostRouteSaved := deleteHostRoute
	defer func() {
		hostLinkByName = hostLinkByNameSaved
		deleteHostRoute = deleteHostRouteSaved
	}()

	hostLinkByName = func(name string) (netlink.Link, error) {
		assert.Check(t, is.Equal(name, "nkhost0"))
		return &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: name, Index: 7}}, nil
	}
	var deleted []netlink.Route
	deleteHostRoute = func(route *netlink.Route) error {
		deleted = append(deleted, *route)
		return nil
	}

	assert.NilError(t, d.Leave("dummy", "ep1"))
	assert.Check(t, is.Len(epDatapath.removedLocalEndpoints, 1))
	assert.Check(t, is.Equal(epDatapath.removedLocalEndpoints[0].HostIf, "nkhost0"))
	assert.Check(t, is.Equal(epDatapath.removedLocalEndpoints[0].Addr.IP.String(), "172.31.0.11"))
	assert.Check(t, is.Len(deleted, 1))
	assert.Check(t, is.Equal(deleted[0].LinkIndex, 7))
	assert.Check(t, is.DeepEqual(deleted[0].Dst, &net.IPNet{
		IP:   net.ParseIP("172.31.0.11").To4(),
		Mask: net.CIDRMask(32, 32),
	}))
}

func TestDeleteEndpointDetachesEndpointNetkitDatapath(t *testing.T) {
	store := storeutils.NewTempStore(t)
	epDatapath := &fakeEndpointNetkitDatapath{}
	d := &driver{
		store:            store,
		networks:         map[string]*network{},
		parents:          map[string]*parentRuntime{},
		endpointDatapath: epDatapath,
	}
	nw := &network{
		id:     "dummy",
		driver: d,
		config: &configuration{ID: "dummy"},
		endpoints: map[string]*endpoint{
			"ep1": {
				id:     "ep1",
				nid:    "dummy",
				hostIf: "nkhost0",
			},
		},
	}
	d.networks[nw.id] = nw

	assert.NilError(t, d.DeleteEndpoint("dummy", "ep1"))
	assert.DeepEqual(t, epDatapath.detached, []string{"nkhost0"})
}

func TestDifferentPublishedPortScopesShareDriverDatapath(t *testing.T) {
	datapath := &fakePublishedPortDatapath{}
	newPublishedPortDatapathSaved := newPublishedPortDatapath
	creations := 0
	var createdScopes []string
	newPublishedPortDatapath = func(_ context.Context, scope string) (publishedPortDatapath, error) {
		creations++
		createdScopes = append(createdScopes, scope)
		return datapath, nil
	}
	defer func() {
		newPublishedPortDatapath = newPublishedPortDatapathSaved
	}()

	pms := &drvregistry.PortMappers{}
	assert.NilError(t, pms.Register("nat", &stubPortMapper{}))

	d := &driver{
		portmappers:  pms,
		bridgeConfig: bridge.Configuration{},
		parents:      map[string]*parentRuntime{},
	}

	d.configNetwork.Lock()
	_, err := d.acquireParentRuntimeLocked(context.Background(), "br-a")
	d.configNetwork.Unlock()
	assert.NilError(t, err)

	d.configNetwork.Lock()
	_, err = d.acquireParentRuntimeLocked(context.Background(), "br-b")
	d.configNetwork.Unlock()
	assert.NilError(t, err)

	assert.Check(t, is.Equal(creations, 1))
	assert.DeepEqual(t, createdScopes, []string{"br-a"})
	assert.DeepEqual(t, datapath.addedParents, []string(nil))

	d.configNetwork.Lock()
	err = d.releaseParentRuntimeLocked(context.Background(), "br-a")
	d.configNetwork.Unlock()
	assert.NilError(t, err)
	assert.DeepEqual(t, datapath.removedParents, []string(nil))
	assert.Check(t, is.Equal(datapath.closeCalls, 0))

	d.configNetwork.Lock()
	err = d.releaseParentRuntimeLocked(context.Background(), "br-b")
	d.configNetwork.Unlock()
	assert.NilError(t, err)
	assert.DeepEqual(t, datapath.removedParents, []string(nil))
	assert.Check(t, is.Equal(datapath.closeCalls, 1))
}

func TestEndpointJSONPersistsPublishedPortState(t *testing.T) {
	ep := &endpoint{
		id:      "ep1",
		nid:     "n1",
		srcName: "eth0",
		extConnConfig: &connectivityConfiguration{
			PortBindings: []portmapperapi.PortBindingReq{{
				PortBinding: types.PortBinding{Proto: types.TCP, Port: 80, HostPort: 8080},
				Mapper:      "nat",
			}},
		},
		portMapping: []portmapperapi.PortBinding{{
			PortBinding: types.PortBinding{Proto: types.TCP, IP: net.ParseIP("172.30.0.11"), Port: 80, HostPort: 8080, HostPortEnd: 8080},
			Mapper:      "nat",
		}},
		portBindingState: portBindingMode{routed: true, ipv4: true},
		publishedParent:  "br-test",
	}

	raw, err := ep.MarshalJSON()
	assert.NilError(t, err)

	var restored endpoint
	assert.NilError(t, restored.UnmarshalJSON(raw))
	assert.Check(t, restored.extConnConfig != nil)
	assert.Check(t, is.Equal(len(restored.extConnConfig.PortBindings), 1))
	assert.Check(t, is.Equal(len(restored.portMapping), 1))
	assert.Check(t, is.Equal(restored.portMapping[0].HostPort, uint16(8080)))
	assert.Check(t, is.Equal(restored.portBindingState, ep.portBindingState))
	assert.Check(t, is.Equal(restored.publishedParent, "br-test"))
}

func TestPopulateEndpointsRestoresPublishedPorts(t *testing.T) {
	store := storeutils.NewTempStore(t)

	ep4 := mustParseCIDR(t, "172.30.0.11/24")
	restored := &endpoint{
		id:      "ep1",
		nid:     "n1",
		srcName: "nkcont0",
		hostIf:  "nkhost0",
		addr:    ep4,
		extConnConfig: &connectivityConfiguration{
			PortBindings: []portmapperapi.PortBindingReq{{
				PortBinding: types.PortBinding{
					Proto:       types.TCP,
					Port:        80,
					HostPort:    8000,
					HostPortEnd: 8010,
				},
			}},
		},
		portMapping: []portmapperapi.PortBinding{{
			PortBinding: types.PortBinding{
				Proto:       types.TCP,
				IP:          net.ParseIP("172.30.0.11"),
				Port:        80,
				HostIP:      net.IPv4zero,
				HostPort:    8080,
				HostPortEnd: 8090,
			},
			Mapper: "nat",
		}},
		portBindingState: portBindingMode{routed: true, ipv4: true},
		publishedParent:  "legacy-parent",
	}
	assert.NilError(t, store.PutObjectAtomic(restored))

	runtime := &fakePublishedPortRuntime{}
	epDatapath := &fakeEndpointNetkitDatapath{}
	d := &driver{
		store: store,
		newEndpointDatapath: func(context.Context) (endpointNetkitDatapath, error) {
			return epDatapath, nil
		},
		networks: map[string]*network{
			"n1": {
				id: "n1",
				config: &configuration{
					ID: "n1",
				},
				endpoints: map[string]*endpoint{},
			},
		},
		parents: map[string]*parentRuntime{},
		newPortRuntime: func(context.Context, string) (publishedPortRuntime, error) {
			return runtime, nil
		},
	}

	assert.NilError(t, d.populateEndpoints())
	assert.Check(t, is.Equal(runtime.addEndpointCalls, 1))
	assert.Check(t, is.Equal(runtime.addedEndpoints[0].HostIf, "nkhost0"))
	assert.Check(t, is.Equal(len(runtime.reconcileCalls), 1))
	assert.Check(t, is.Equal(len(d.parents), 1))
	if _, ok := d.parents["n1"]; !ok {
		t.Fatalf("expected restored published-port runtime to use network scope key")
	}
	assert.Check(t, is.Equal(runtime.reconcileCalls[0].DesiredMode, (portBindingMode{routed: true, ipv4: true})))
	assert.Check(t, is.Len(runtime.reconcileCalls[0].PortBindings, 1))
	assert.Check(t, is.Equal(runtime.reconcileCalls[0].PortBindings[0].HostPort, uint16(8080)))
	assert.Check(t, is.Equal(runtime.reconcileCalls[0].PortBindings[0].HostPortEnd, uint16(8080)))

	n, err := d.getNetwork("n1")
	assert.NilError(t, err)
	ep, err := n.endpoint("ep1")
	assert.NilError(t, err)
	assert.Check(t, is.Equal(ep.publishedParent, "n1"))
	assert.Check(t, is.Len(ep.portMapping, 1))
	assert.Check(t, is.Equal(ep.portMapping[0].HostPort, uint16(8080)))
	assert.Check(t, is.Equal(ep.portMapping[0].HostPortEnd, uint16(8080)))
	assert.DeepEqual(t, epDatapath.attached, []string{"nkhost0"})
}

func TestPopulateEndpointsRestoresEgressBeforeAttachingSharedDatapath(t *testing.T) {
	store := storeutils.NewTempStore(t)
	restored := &endpoint{
		id:      "ep1",
		nid:     "n1",
		srcName: "nkcont0",
		hostIf:  "nkhost0",
		addr:    mustParseCIDR(t, "172.30.0.11/24"),
	}
	assert.NilError(t, store.PutObjectAtomic(restored))

	sharedDatapath := &fakePublishedPortDatapath{}
	standaloneDatapath := &fakeEndpointNetkitDatapath{}
	newPublishedPortDatapathSaved := newPublishedPortDatapath
	newPublishedPortDatapath = func(context.Context, string) (publishedPortDatapath, error) {
		return sharedDatapath, nil
	}
	defer func() {
		newPublishedPortDatapath = newPublishedPortDatapathSaved
	}()

	d := &driver{
		store: store,
		newEndpointDatapath: func(context.Context) (endpointNetkitDatapath, error) {
			return standaloneDatapath, nil
		},
		networks: map[string]*network{
			"n1": {
				id: "n1",
				config: &configuration{
					ID:                 "n1",
					EnableIPMasquerade: true,
					GwModeIPv4:         gwModeNAT,
				},
				endpoints: map[string]*endpoint{},
			},
		},
		parents:           map[string]*parentRuntime{},
		datapathEndpoints: map[string]struct{}{},
	}

	assert.NilError(t, d.populateEndpoints())
	assert.DeepEqual(t, sharedDatapath.attached, []string{"nkhost0"})
	assert.DeepEqual(t, standaloneDatapath.attached, []string(nil))
	assert.Assert(t, is.Len(sharedDatapath.upsertedEndpoints, 1))
	assert.Check(t, sharedDatapath.upsertedEndpoints[0].Addr.IP.Equal(net.ParseIP("172.30.0.11")))
}

func TestBridgePublishedPortRuntimeAllocatesIPv4PublishedPorts(t *testing.T) {
	datapath := &fakePublishedPortDatapath{}
	newPublishedPortDatapathSaved := newPublishedPortDatapath
	newPublishedPortDatapath = func(context.Context, string) (publishedPortDatapath, error) {
		return datapath, nil
	}
	defer func() {
		newPublishedPortDatapath = newPublishedPortDatapathSaved
	}()

	pms := &drvregistry.PortMappers{}
	natPM := &stubPortMapper{}
	assert.NilError(t, pms.Register("nat", natPM))

	rtAny, err := newBridgePublishedPortRuntime(context.Background(), "br-test", bridge.Configuration{}, pms)
	assert.NilError(t, err)

	rt := rtAny.(*bridgePublishedPortRuntime)
	ep4 := mustParseCIDR(t, "172.30.0.0/24")
	ep4.IP = net.ParseIP("172.30.0.11")
	assert.NilError(t, rt.AddEndpoint(context.Background(), publishedEndpointConfig{HostIf: "nk123", Addr: ep4}))

	pbs, err := rt.ReconcilePortBindings(context.Background(), publishedPortRequest{
		Addr: ep4,
		PortBindings: []portmapperapi.PortBindingReq{{
			PortBinding: types.PortBinding{
				Proto:    types.TCP,
				Port:     80,
				HostPort: 8080,
			},
		}},
		DesiredMode: portBindingMode{ipv4: true},
	})
	assert.NilError(t, err)
	assert.Check(t, is.Len(pbs, 1))
	assert.Check(t, is.Equal(pbs[0].Mapper, "nat"))
	assert.Check(t, is.Equal(pbs[0].HostPort, uint16(8080)))
	assert.Check(t, is.Equal(len(natPM.reqs), 1))
	assert.Check(t, is.Equal(natPM.reqs[0][0].HostPort, uint16(8080)))
	assert.Check(t, is.Equal(len(datapath.added), 1))
	assert.Check(t, is.Equal(datapath.added[0][0].HostPort, uint16(8080)))
}

func TestBridgePublishedPortRuntimeUsesRoutedMapperWhenNATDisabled(t *testing.T) {
	datapath := &fakePublishedPortDatapath{}
	pms := &drvregistry.PortMappers{}
	assert.NilError(t, pms.Register("nat", &stubPortMapper{}))
	assert.NilError(t, routed.Register(pms))

	rtAny, err := newBridgePublishedPortRuntimeWithDatapath("net1", pms, datapath, false)
	assert.NilError(t, err)
	rt := rtAny.(*bridgePublishedPortRuntime)

	ep4 := mustParseCIDR(t, "172.30.0.11/24")
	assert.NilError(t, rt.AddEndpoint(context.Background(), publishedEndpointConfig{HostIf: "nk123", Addr: ep4}))

	pbs, err := rt.ReconcilePortBindings(context.Background(), publishedPortRequest{
		Addr: ep4,
		PortBindings: []portmapperapi.PortBindingReq{{
			PortBinding: types.PortBinding{
				Proto:    types.TCP,
				Port:     80,
				HostIP:   net.ParseIP("192.0.2.10"),
				HostPort: 8080,
			},
		}},
		DesiredMode:    portBindingMode{routed: true},
		DisableNATIPv4: true,
	})
	assert.NilError(t, err)
	assert.Assert(t, is.Len(pbs, 1))
	assert.Check(t, is.Equal(pbs[0].Mapper, "routed"))
	assert.Check(t, pbs[0].Forwarding)
	assert.Check(t, pbs[0].HostIP.Equal(net.IPv4zero))
	assert.Check(t, is.Equal(pbs[0].HostPort, uint16(0)))
	assert.Check(t, is.Len(datapath.added, 0))
}

func TestDeleteNetworkReleasesPublishedPorts(t *testing.T) {
	runtime := &fakePublishedPortRuntime{}
	d := &driver{
		networks: map[string]*network{},
		parents: map[string]*parentRuntime{
			"n1": {
				parent:  "n1",
				runtime: runtime,
				refs:    1,
			},
		},
		datapathEndpoints: map[string]struct{}{},
	}
	nw := &network{
		id:     "n1",
		driver: d,
		config: &configuration{ID: "n1"},
		endpoints: map[string]*endpoint{
			"ep1": {
				id:              "ep1",
				nid:             "n1",
				hostIf:          "nkhost0",
				addr:            mustParseCIDR(t, "172.30.0.11/24"),
				publishedParent: "n1",
				portBindingState: portBindingMode{
					routed: true,
					ipv4:   true,
				},
				portMapping: []portmapperapi.PortBinding{{
					PortBinding: types.PortBinding{
						Proto:    types.TCP,
						IP:       net.ParseIP("172.30.0.11"),
						Port:     80,
						HostIP:   net.IPv4zero,
						HostPort: 8080,
					},
					Mapper: "nat",
				}},
			},
		},
	}
	d.networks[nw.id] = nw

	hostLinkByNameSaved := hostLinkByName
	deleteHostRouteSaved := deleteHostRoute
	hostLinkByName = func(name string) (netlink.Link, error) {
		return &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: name, Index: 7}}, nil
	}
	deleteHostRoute = func(*netlink.Route) error { return nil }
	defer func() {
		hostLinkByName = hostLinkByNameSaved
		deleteHostRoute = deleteHostRouteSaved
	}()

	assert.NilError(t, d.DeleteNetwork("n1"))
	assert.Check(t, is.Equal(len(runtime.released), 1))
	assert.Check(t, is.Equal(runtime.delEndpointCalls, 1))
	assert.Check(t, is.Equal(runtime.closeCalls, 1))
	assert.Check(t, is.Equal(len(d.parents), 0))
}

func TestBridgePublishedPortRuntimeProgramsPublishedEndpointForRedirect(t *testing.T) {
	datapath := &fakePublishedPortDatapath{}
	pms := &drvregistry.PortMappers{}
	assert.NilError(t, pms.Register("nat", &stubPortMapper{}))

	rtAny, err := newBridgePublishedPortRuntimeWithDatapath("net1", pms, datapath, false)
	assert.NilError(t, err)

	rt := rtAny.(*bridgePublishedPortRuntime)
	ep4 := mustParseCIDR(t, "172.30.0.11/24")
	ep6 := mustParseCIDR(t, "2001:db8::11/64")
	ep := publishedEndpointConfig{
		HostIf: "nk123",
		Addr:   ep4,
		Addrv6: ep6,
	}

	assert.NilError(t, rt.AddEndpoint(context.Background(), ep))
	assert.Assert(t, is.Len(datapath.addedPublishedEndpoints, 1))
	assert.Check(t, is.Equal(datapath.addedPublishedEndpoints[0].HostIf, "nk123"))
	assert.Check(t, datapath.addedPublishedEndpoints[0].Addr.IP.Equal(net.ParseIP("172.30.0.11")))
	assert.Check(t, datapath.addedPublishedEndpoints[0].Addrv6.IP.Equal(net.ParseIP("2001:db8::11")))

	assert.NilError(t, rt.DelEndpoint(context.Background(), ep))
	assert.Assert(t, is.Len(datapath.removedPublishedEndpoints, 1))
	assert.Check(t, is.Equal(datapath.removedPublishedEndpoints[0].HostIf, "nk123"))
	assert.Check(t, datapath.removedPublishedEndpoints[0].Addr.IP.Equal(net.ParseIP("172.30.0.11")))
	assert.Check(t, datapath.removedPublishedEndpoints[0].Addrv6.IP.Equal(net.ParseIP("2001:db8::11")))
}

func TestEBPFPublishedPortDatapathTracksPublishedEndpointIfindex(t *testing.T) {
	hostLinkByNameSaved := hostLinkByName
	hostLinkByName = func(name string) (netlink.Link, error) {
		return &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: name, Index: 123}}, nil
	}
	defer func() {
		hostLinkByName = hostLinkByNameSaved
	}()

	dp := &ebpfPublishedPortDatapath{
		publishedEndpointIfindexV4: map[uint32]uint32{},
		publishedEndpointIfindexV6: map[[16]byte]uint32{},
	}
	ep4 := mustParseCIDR(t, "172.30.0.11/24")
	ep6 := mustParseCIDR(t, "2001:db8::11/64")

	assert.NilError(t, dp.AddPublishedEndpoint(publishedEndpointConfig{
		HostIf: "nk123",
		Addr:   ep4,
		Addrv6: ep6,
	}))
	key4, err := publishedEndpointKeyV4(ep4)
	assert.NilError(t, err)
	key6, err := publishedEndpointKeyV6(ep6)
	assert.NilError(t, err)
	assert.Check(t, is.Equal(dp.publishedEndpointIfindexV4[key4], uint32(123)))
	assert.Check(t, is.Equal(dp.publishedEndpointIfindexV6[key6], uint32(123)))

	assert.NilError(t, dp.RemovePublishedEndpoint(publishedEndpointConfig{
		HostIf: "nk123",
		Addr:   ep4,
		Addrv6: ep6,
	}))
	_, ok4 := dp.publishedEndpointIfindexV4[key4]
	_, ok6 := dp.publishedEndpointIfindexV6[key6]
	assert.Check(t, !ok4)
	assert.Check(t, !ok6)
}

func TestBridgePublishedPortRuntimeKeepsHostPortWhenAddingIPv6(t *testing.T) {
	isV6ListenableSaved := isV6Listenable
	isV6Listenable = func() bool { return true }
	defer func() {
		isV6Listenable = isV6ListenableSaved
	}()

	datapath := &fakePublishedPortDatapath{}
	newPublishedPortDatapathSaved := newPublishedPortDatapath
	newPublishedPortDatapath = func(context.Context, string) (publishedPortDatapath, error) {
		return datapath, nil
	}
	defer func() {
		newPublishedPortDatapath = newPublishedPortDatapathSaved
	}()

	pms := &drvregistry.PortMappers{}
	natPM := &stubPortMapper{}
	assert.NilError(t, pms.Register("nat", natPM))

	rtAny, err := newBridgePublishedPortRuntime(context.Background(), "br-test", bridge.Configuration{}, pms)
	assert.NilError(t, err)

	rt := rtAny.(*bridgePublishedPortRuntime)
	ep4 := mustParseCIDR(t, "172.30.0.0/24")
	ep4.IP = net.ParseIP("172.30.0.11")
	_, ep6, err := net.ParseCIDR("fd00::11/64")
	assert.NilError(t, err)
	ep6.IP = net.ParseIP("fd00::11")
	assert.NilError(t, rt.AddEndpoint(context.Background(), publishedEndpointConfig{HostIf: "nk123", Addr: ep4, Addrv6: ep6}))

	current, err := rt.ReconcilePortBindings(context.Background(), publishedPortRequest{
		Addr:   ep4,
		Addrv6: ep6,
		PortBindings: []portmapperapi.PortBindingReq{{
			PortBinding: types.PortBinding{
				Proto:    types.TCP,
				Port:     80,
				HostPort: 8080,
			},
		}},
		DesiredMode: portBindingMode{ipv4: true},
	})
	assert.NilError(t, err)
	assert.Check(t, is.Len(current, 1))

	expanded, err := rt.ReconcilePortBindings(context.Background(), publishedPortRequest{
		Addr:         ep4,
		Addrv6:       ep6,
		PortBindings: []portmapperapi.PortBindingReq{{PortBinding: types.PortBinding{Proto: types.TCP, Port: 80}}},
		Current:      current,
		CurrentMode:  portBindingMode{ipv4: true},
		DesiredMode:  portBindingMode{ipv4: true, ipv6: true},
	})
	assert.NilError(t, err)
	assert.Check(t, is.Len(expanded, 2))
	assert.Check(t, is.Equal(expanded[0].HostPort, expanded[1].HostPort))
	assert.Check(t, is.Equal(len(natPM.reqs), 2))
	assert.Check(t, is.Equal(natPM.reqs[1][0].HostPort, uint16(8080)))
	assert.Check(t, is.Equal(len(datapath.added), 2))
	assert.Check(t, is.Equal(datapath.added[1][0].HostPort, uint16(8080)))
}

func TestBridgePublishedPortRuntimeRejectsRootlessPortDrivers(t *testing.T) {
	datapath := &fakePublishedPortDatapath{}
	newPublishedPortDatapathSaved := newPublishedPortDatapath
	newPublishedPortDatapath = func(context.Context, string) (publishedPortDatapath, error) {
		return datapath, nil
	}
	defer func() {
		newPublishedPortDatapath = newPublishedPortDatapathSaved
	}()

	pms := &drvregistry.PortMappers{}
	assert.NilError(t, pms.Register("nat", rootlessPortMapper{}))

	rtAny, err := newBridgePublishedPortRuntime(context.Background(), "br-test", bridge.Configuration{}, pms)
	assert.NilError(t, err)

	rt := rtAny.(*bridgePublishedPortRuntime)
	ep4 := mustParseCIDR(t, "172.30.0.11/24")
	assert.NilError(t, rt.AddEndpoint(context.Background(), publishedEndpointConfig{HostIf: "nk123", Addr: ep4}))

	_, err = rt.ReconcilePortBindings(context.Background(), publishedPortRequest{
		Addr: ep4,
		PortBindings: []portmapperapi.PortBindingReq{{
			PortBinding: types.PortBinding{
				Proto:       types.TCP,
				Port:        80,
				HostIP:      net.IPv4zero,
				HostPort:    8080,
				HostPortEnd: 8080,
			},
			Mapper: "nat",
		}},
		DesiredMode: portBindingMode{ipv4: true},
	})
	assert.Check(t, err != nil)
	assert.Check(t, is.ErrorContains(err, "rootless"))
}

func TestBridgePublishedPortRuntimeRollsBackMappedBatchesOnMapFailure(t *testing.T) {
	pms := &drvregistry.PortMappers{}
	natPM := &stubPortMapper{failOnCall: 2}
	assert.NilError(t, pms.Register("nat", natPM))

	rt := &bridgePublishedPortRuntime{portmappers: pms}
	_, err := rt.mapPortBindingReqs(context.Background(), []portmapperapi.PortBindingReq{
		{
			PortBinding: types.PortBinding{
				Proto:       types.TCP,
				IP:          net.ParseIP("172.30.0.11"),
				Port:        80,
				HostIP:      net.IPv4zero,
				HostPort:    8080,
				HostPortEnd: 8080,
			},
			Mapper: "nat",
		},
		{
			PortBinding: types.PortBinding{
				Proto:       types.TCP,
				IP:          net.ParseIP("172.30.0.11"),
				Port:        81,
				HostIP:      net.IPv4zero,
				HostPort:    8081,
				HostPortEnd: 8081,
			},
			Mapper: "nat",
		},
	})

	assert.Check(t, err != nil)
	assert.Check(t, is.ErrorContains(err, "stubPortMapper.MapPorts"))
	assert.Check(t, is.Len(natPM.mapped, 0))
	assert.Assert(t, is.Len(natPM.unmapped, 1))
	assert.Check(t, is.Equal(natPM.unmapped[0][0].HostPort, uint16(8080)))
}

func TestBridgePublishedPortRuntimeReleaseRemovesDatapathBindings(t *testing.T) {
	datapath := &fakePublishedPortDatapath{}
	newPublishedPortDatapathSaved := newPublishedPortDatapath
	newPublishedPortDatapath = func(context.Context, string) (publishedPortDatapath, error) {
		return datapath, nil
	}
	defer func() {
		newPublishedPortDatapath = newPublishedPortDatapathSaved
	}()

	pms := &drvregistry.PortMappers{}
	natPM := &stubPortMapper{}
	assert.NilError(t, pms.Register("nat", natPM))

	rtAny, err := newBridgePublishedPortRuntime(context.Background(), "br-test", bridge.Configuration{}, pms)
	assert.NilError(t, err)

	rt := rtAny.(*bridgePublishedPortRuntime)
	ep4 := mustParseCIDR(t, "172.30.0.11/24")
	assert.NilError(t, rt.AddEndpoint(context.Background(), publishedEndpointConfig{HostIf: "nk123", Addr: ep4}))

	pbs, err := rt.ReconcilePortBindings(context.Background(), publishedPortRequest{
		Addr: ep4,
		PortBindings: []portmapperapi.PortBindingReq{{
			PortBinding: types.PortBinding{Proto: types.TCP, Port: 80, HostPort: 8080},
		}},
		DesiredMode: portBindingMode{ipv4: true},
	})
	assert.NilError(t, err)
	assert.NilError(t, rt.ReleasePortBindings(context.Background(), pbs))
	assert.Check(t, is.Equal(len(datapath.removed), 1))
	assert.Check(t, is.Equal(datapath.removed[0][0].HostPort, uint16(8080)))
}

func TestBridgePublishedPortRuntimeCloseClosesDatapath(t *testing.T) {
	datapath := &fakePublishedPortDatapath{}
	newPublishedPortDatapathSaved := newPublishedPortDatapath
	newPublishedPortDatapath = func(context.Context, string) (publishedPortDatapath, error) {
		return datapath, nil
	}
	defer func() {
		newPublishedPortDatapath = newPublishedPortDatapathSaved
	}()

	pms := &drvregistry.PortMappers{}
	assert.NilError(t, pms.Register("nat", &stubPortMapper{}))

	rtAny, err := newBridgePublishedPortRuntime(context.Background(), "br-test", bridge.Configuration{}, pms)
	assert.NilError(t, err)

	rt := rtAny.(*bridgePublishedPortRuntime)
	assert.NilError(t, rt.Close(context.Background()))
	assert.Check(t, is.Equal(datapath.closeCalls, 1))
}

func TestBridgePublishedPortRuntimeFailsWhenDatapathInitFails(t *testing.T) {
	newPublishedPortDatapathSaved := newPublishedPortDatapath
	newPublishedPortDatapath = func(context.Context, string) (publishedPortDatapath, error) {
		return nil, errors.New("attach tcx link: unsupported")
	}
	defer func() {
		newPublishedPortDatapath = newPublishedPortDatapathSaved
	}()

	pms := &drvregistry.PortMappers{}
	assert.NilError(t, pms.Register("nat", &stubPortMapper{}))

	_, err := newBridgePublishedPortRuntime(context.Background(), "br-test", bridge.Configuration{}, pms)
	assert.Check(t, err != nil)
	assert.Check(t, is.ErrorContains(err, "unsupported"))
}

func TestHostFacingLinkIndicesExcludeParentLoopbackAndBridgeSlaves(t *testing.T) {
	parent := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: "br-master", Index: 10}}
	links := []netlink.Link{
		&netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: "lo", Index: 1}},
		&netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: "eth0", Index: 2}},
		&netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: "br-master", Index: 10}},
		&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "nkhost0", Index: 11, MasterIndex: 10}},
		&netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: "br-alt", Index: 20}},
		&netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: "uplink1", Index: 21}},
		&netlink.Device{LinkAttrs: netlink.LinkAttrs{}},
	}

	assert.DeepEqual(t, hostFacingLinkIndices(parent, links), []int{2, 20, 21})
}

func TestHostFacingLinkIndicesWithoutParentIncludesNonLoopbackLinks(t *testing.T) {
	links := []netlink.Link{
		&netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: "lo", Index: 1}},
		&netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: "eth0", Index: 2}},
		&netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: "nk0", Index: 3}},
		&netlink.Netkit{LinkAttrs: netlink.LinkAttrs{Name: "nkhost0", Index: 4}},
		&netlink.Device{LinkAttrs: netlink.LinkAttrs{}},
	}

	assert.DeepEqual(t, hostFacingLinkIndices(nil, links), []int{2, 3})
}

func TestBridgeSlaveLinkIndicesIncludeParentMembers(t *testing.T) {
	parent := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: "br-master", Index: 10}}
	links := []netlink.Link{
		&netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: "eth0", Index: 2}},
		&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "nkhost0", Index: 11, MasterIndex: 10}},
		&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "nkhost1", Index: 12, MasterIndex: 10}},
		&netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: "br-alt", Index: 20}},
	}

	assert.DeepEqual(t, bridgeSlaveLinkIndices(parent, links), []int{11, 12})
}

func TestPublishedPortGlobalTCXAttachmentsIncludeHostFacingEgress(t *testing.T) {
	assert.DeepEqual(t, publishedPortGlobalTCXAttachments([]int{2, 20}), []publishedPortTCXAttachment{
		{Ifindex: 2, Attach: ebpf.AttachTCXIngress},
		{Ifindex: 2, Attach: ebpf.AttachTCXEgress},
		{Ifindex: 20, Attach: ebpf.AttachTCXIngress},
		{Ifindex: 20, Attach: ebpf.AttachTCXEgress},
	})
}

func TestPublishedPortParentTCXAttachmentsIncludeBridgeSlaves(t *testing.T) {
	assert.DeepEqual(t, publishedPortParentTCXAttachments(10, []int{11, 12}), []publishedPortTCXAttachment{
		{Ifindex: 10, Attach: ebpf.AttachTCXIngress},
		{Ifindex: 10, Attach: ebpf.AttachTCXEgress},
		{Ifindex: 11, Attach: ebpf.AttachTCXIngress},
		{Ifindex: 11, Attach: ebpf.AttachTCXEgress},
		{Ifindex: 12, Attach: ebpf.AttachTCXIngress},
		{Ifindex: 12, Attach: ebpf.AttachTCXEgress},
	})
}

func TestPublishedPortHostSocketAttachTypes(t *testing.T) {
	assert.DeepEqual(t, publishedPortCgroupAttachTypes(), []ebpf.AttachType{
		ebpf.AttachCGroupInet4Connect,
		ebpf.AttachCGroupInet6Connect,
		ebpf.AttachCGroupUDP4Sendmsg,
		ebpf.AttachCGroupUDP6Sendmsg,
		ebpf.AttachCgroupInet4GetPeername,
		ebpf.AttachCgroupInet6GetPeername,
	})
}

func TestLoadNetkitPortmapIncludesPublishedPortMaps(t *testing.T) {
	spec, err := loadNetkitPortmap()
	assert.NilError(t, err)
	assert.Check(t, spec != nil)
	assert.Check(t, spec.Programs["portmap_ingress"] != nil)
	assert.Check(t, spec.Programs["portmap_egress"] != nil)
	assert.Check(t, spec.Programs["endpoint_primary"] != nil)
	assert.Check(t, spec.Programs["endpoint_peer"] != nil)
	assert.Check(t, spec.Programs["connect4"] != nil)
	assert.Check(t, spec.Programs["connect6"] != nil)
	assert.Check(t, spec.Programs["sendmsg4"] != nil)
	assert.Check(t, spec.Programs["sendmsg6"] != nil)
	assert.Check(t, spec.Programs["getpeername4"] != nil)
	assert.Check(t, spec.Programs["getpeername6"] != nil)
	assert.Check(t, spec.Maps["egress_endpoints_v4"] != nil)
	assert.Check(t, spec.Maps["egress_endpoints_v6"] != nil)
	assert.Check(t, spec.Maps["egress_flows_v4"] != nil)
	assert.Check(t, spec.Maps["egress_flows_v6"] != nil)
	assert.Check(t, spec.Maps["egress_ifaces"] != nil)
	assert.Check(t, spec.Maps["local_sources"] != nil)
	assert.Check(t, spec.Maps["local_endpoints_v4"] != nil)
	assert.Check(t, spec.Maps["local_endpoints_v6"] != nil)
	assert.Check(t, spec.Maps["published_ports_v4"] != nil)
	assert.Check(t, spec.Maps["published_ports_v6"] != nil)
	assert.Check(t, spec.Maps["published_flows_v4"] != nil)
	assert.Check(t, spec.Maps["published_flows_v6"] != nil)
	assert.Check(t, spec.Maps["published_sock_v4"] != nil)
	assert.Check(t, spec.Maps["published_sock_v6"] != nil)
	assert.Check(t, spec.Maps["published_ifaces"] != nil)
}

func TestBPFIPv4ParserOnlyAcceptsICMPAmongUnsupportedL4(t *testing.T) {
	raw, err := os.ReadFile("bpf/netkit_portmap.c")
	assert.NilError(t, err)

	src := string(raw)
	expected := "if (pkt->proto == IPPROTO_ICMP) {\n" +
		"\t\t\tstruct icmphdr *icmph = data + pkt->l4_off;\n" +
		"\n" +
		"\t\t\tif ((void *)(icmph + 1) > data_end)\n" +
		"\t\t\t\treturn -1;\n" +
		"\t\t\tpkt->l4_csum_off = pkt->l4_off + offsetof(struct icmphdr, checksum);\n" +
		"\t\t\tif (icmph->type == ICMP_ECHO || icmph->type == ICMP_ECHOREPLY) {\n" +
		"\t\t\t\tpkt->sport = icmph->un.echo.id;\n" +
		"\t\t\t\tpkt->dport = icmph->un.echo.id;\n" +
		"\t\t\t}\n" +
		"\t\t\treturn 0;\n" +
		"\t\t}\n" +
		"\n" +
		"\t\treturn -1;"
	assert.Check(t, strings.Contains(src, expected), "IPv4 parser must only accept ICMP after TCP/UDP; other protocols must remain unsupported")
}

func TestBPFIPv6ParserHandlesBigTCPJumboHopByHopHeader(t *testing.T) {
	raw, err := os.ReadFile("bpf/netkit_portmap.c")
	assert.NilError(t, err)

	src := string(raw)
	for _, expected := range []string{
		"static __always_inline int parse_ipv6_l4(struct __sk_buff *skb, struct packet_info *pkt,",
		"struct hop_jumbo_hdr *hop = data + pkt->l4_off;",
		"if (ip6h->payload_len == 0 && ip6h->nexthdr == NEXTHDR_HOP) {",
		"if (hop->tlv_type != IPV6_TLV_JUMBO || hop->tlv_len != sizeof(hop->jumbo_payload_len))",
		"pkt->proto = hop->nexthdr;",
		"pkt->l3_len = bpf_ntohl(hop->jumbo_payload_len) + sizeof(*ip6h);",
		"pkt->l4_off += sizeof(*hop);",
	} {
		assert.Check(t, strings.Contains(src, expected), "IPv6 parser must handle BIG TCP Hop-by-Hop jumbo option: missing %q", expected)
	}
}

func TestClassifyPublishedPortDatapathErrorUnsupportedIsNotImplemented(t *testing.T) {
	err := classifyPublishedPortDatapathError("load netkit published-port bpf objects", errors.New("unknown func bpf_skb_ct_alloc"))
	assert.Check(t, err != nil)
	assert.Check(t, cerrdefs.IsNotImplemented(err))
	assert.Check(t, is.ErrorContains(err, "unsupported on this kernel"))
}

func TestClassifyPublishedPortDatapathErrorMissingCgroupV2IsNotImplemented(t *testing.T) {
	err := classifyPublishedPortDatapathError("attach published-port host socket programs", errors.New("cgroup v2 unified mode required"))
	assert.Check(t, err != nil)
	assert.Check(t, cerrdefs.IsNotImplemented(err))
	assert.Check(t, is.ErrorContains(err, "unsupported on this kernel"))
}

func mustParseCIDR(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	ip, nw, err := net.ParseCIDR(cidr)
	assert.NilError(t, err)
	nw.IP = ip
	return nw
}

type stubPortMapper struct {
	reqs       [][]portmapperapi.PortBindingReq
	mapped     []portmapperapi.PortBinding
	unmapped   [][]portmapperapi.PortBinding
	failOnCall int
}

func (pm *stubPortMapper) MapPorts(_ context.Context, reqs []portmapperapi.PortBindingReq) ([]portmapperapi.PortBinding, error) {
	if len(reqs) == 0 {
		return []portmapperapi.PortBinding{}, nil
	}
	if pm.failOnCall != 0 && len(pm.reqs)+1 == pm.failOnCall {
		return nil, fmt.Errorf("stubPortMapper.MapPorts failure on call %d", pm.failOnCall)
	}
	pm.reqs = append(pm.reqs, sliceutil.Map(reqs, func(req portmapperapi.PortBindingReq) portmapperapi.PortBindingReq {
		return portmapperapi.PortBindingReq{PortBinding: req.Copy(), Mapper: req.Mapper}
	}))
	pbs := sliceutil.Map(reqs, func(req portmapperapi.PortBindingReq) portmapperapi.PortBinding {
		return portmapperapi.PortBinding{PortBinding: req.Copy(), Mapper: req.Mapper}
	})
	pm.mapped = append(pm.mapped, pbs...)
	return pbs, nil
}

func (pm *stubPortMapper) UnmapPorts(_ context.Context, reqs []portmapperapi.PortBinding) error {
	pm.unmapped = append(pm.unmapped, slices.Clone(reqs))
	for _, req := range reqs {
		idx := slices.IndexFunc(pm.mapped, func(pb portmapperapi.PortBinding) bool {
			return pb.Equal(req.PortBinding) && pb.Mapper == req.Mapper
		})
		if idx == -1 {
			return fmt.Errorf("stubPortMapper.UnmapPorts: pb doesn't exist %v", req)
		}
		pm.mapped = slices.Delete(pm.mapped, idx, idx+1)
	}
	return nil
}

type rootlessPortMapper struct{}

func (rootlessPortMapper) MapPorts(_ context.Context, reqs []portmapperapi.PortBindingReq) ([]portmapperapi.PortBinding, error) {
	res := make([]portmapperapi.PortBinding, len(reqs))
	for i, req := range reqs {
		res[i] = portmapperapi.PortBinding{
			PortBinding:      req.Copy(),
			ChildHostIP:      net.IPv4(127, 0, 0, 1),
			PortDriverRemove: func() error { return nil },
		}
	}
	return res, nil
}

func (rootlessPortMapper) UnmapPorts(_ context.Context, _ []portmapperapi.PortBinding) error {
	return nil
}

type fakePublishedPortDatapath struct {
	added                     [][]portmapperapi.PortBinding
	removed                   [][]portmapperapi.PortBinding
	attached                  []string
	detached                  []string
	addedParents              []string
	removedParents            []string
	upsertedEndpoints         []egressEndpointConfig
	removedEndpoints          []egressEndpointConfig
	upsertedLocalEndpoints    []localEndpointConfig
	removedLocalEndpoints     []localEndpointConfig
	addedPublishedEndpoints   []publishedEndpointConfig
	removedPublishedEndpoints []publishedEndpointConfig
	closeCalls                int
}

func (f *fakePublishedPortDatapath) AttachEndpoint(hostIf string) error {
	f.attached = append(f.attached, hostIf)
	return nil
}

func (f *fakePublishedPortDatapath) DetachEndpoint(hostIf string) error {
	f.detached = append(f.detached, hostIf)
	return nil
}

func (f *fakePublishedPortDatapath) AddParent(parent string) error {
	f.addedParents = append(f.addedParents, parent)
	return nil
}

func (f *fakePublishedPortDatapath) RemoveParent(parent string) error {
	f.removedParents = append(f.removedParents, parent)
	return nil
}

func (f *fakePublishedPortDatapath) UpsertEgressEndpoint(ep egressEndpointConfig) error {
	f.upsertedEndpoints = append(f.upsertedEndpoints, ep)
	return nil
}

func (f *fakePublishedPortDatapath) RemoveEgressEndpoint(ep egressEndpointConfig) error {
	f.removedEndpoints = append(f.removedEndpoints, ep)
	return nil
}

func (f *fakePublishedPortDatapath) UpsertLocalEndpoint(ep localEndpointConfig) error {
	f.upsertedLocalEndpoints = append(f.upsertedLocalEndpoints, ep)
	return nil
}

func (f *fakePublishedPortDatapath) RemoveLocalEndpoint(ep localEndpointConfig) error {
	f.removedLocalEndpoints = append(f.removedLocalEndpoints, ep)
	return nil
}

func (f *fakePublishedPortDatapath) AddPublishedEndpoint(ep publishedEndpointConfig) error {
	f.addedPublishedEndpoints = append(f.addedPublishedEndpoints, ep)
	return nil
}

func (f *fakePublishedPortDatapath) RemovePublishedEndpoint(ep publishedEndpointConfig) error {
	f.removedPublishedEndpoints = append(f.removedPublishedEndpoints, ep)
	return nil
}

func (f *fakePublishedPortDatapath) AddBindings(bindings []portmapperapi.PortBinding) error {
	f.added = append(f.added, slices.Clone(bindings))
	return nil
}

func (f *fakePublishedPortDatapath) RemoveBindings(bindings []portmapperapi.PortBinding) error {
	f.removed = append(f.removed, slices.Clone(bindings))
	return nil
}

func (f *fakePublishedPortDatapath) Close() error {
	f.closeCalls++
	return nil
}

type fakeEndpointNetkitDatapath struct {
	attached               []string
	detached               []string
	upsertedLocalEndpoints []localEndpointConfig
	removedLocalEndpoints  []localEndpointConfig
}

func (f *fakeEndpointNetkitDatapath) AttachEndpoint(hostIf string) error {
	f.attached = append(f.attached, hostIf)
	return nil
}

func (f *fakeEndpointNetkitDatapath) DetachEndpoint(hostIf string) error {
	f.detached = append(f.detached, hostIf)
	return nil
}

func (f *fakeEndpointNetkitDatapath) UpsertLocalEndpoint(ep localEndpointConfig) error {
	f.upsertedLocalEndpoints = append(f.upsertedLocalEndpoints, ep)
	return nil
}

func (f *fakeEndpointNetkitDatapath) RemoveLocalEndpoint(ep localEndpointConfig) error {
	f.removedLocalEndpoints = append(f.removedLocalEndpoints, ep)
	return nil
}

func (f *fakeEndpointNetkitDatapath) Close() error {
	return nil
}
