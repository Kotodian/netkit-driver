//go:build linux

package netkit

//go:generate clang -target bpf -O2 -g -D__TARGET_ARCH_x86 -I./bpf -c ./bpf/netkit_portmap.c -o ./bpf/netkit_portmap_bpfel.o

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/moby/moby/v2/daemon/libnetwork/nlwrap"
	"github.com/moby/moby/v2/daemon/libnetwork/ns"
	"github.com/moby/moby/v2/daemon/libnetwork/portmapperapi"
	"github.com/moby/moby/v2/errdefs"
	"github.com/moby/moby/v2/pkg/sysinfo"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const publishedPortFlagLoopbackOnly = 1 << 0
const publishedIfaceFlagRedirectReply = 1 << 0
const egressEndpointFlagMasquerade = 1 << 0
const publishedPortCgroupPath = "/sys/fs/cgroup"

type publishedPortDatapath interface {
	AttachEndpoint(hostIf string) error
	DetachEndpoint(hostIf string) error
	AddParent(parent string) error
	RemoveParent(parent string) error
	UpsertEgressEndpoint(ep egressEndpointConfig) error
	RemoveEgressEndpoint(ep egressEndpointConfig) error
	UpsertLocalEndpoint(ep localEndpointConfig) error
	RemoveLocalEndpoint(ep localEndpointConfig) error
	AddPublishedEndpoint(ep publishedEndpointConfig) error
	RemovePublishedEndpoint(ep publishedEndpointConfig) error
	AddBindings(bindings []portmapperapi.PortBinding) error
	RemoveBindings(bindings []portmapperapi.PortBinding) error
	Close() error
}

var newPublishedPortDatapath = func(ctx context.Context, scope string) (publishedPortDatapath, error) {
	return newEBPFPublishedPortDatapath(ctx, scope)
}

var attachTCX = link.AttachTCX
var attachCgroup = link.AttachCgroup
var listLinks = nlwrap.LinkList
var hostLinkByIndex = func(index int) (netlink.Link, error) {
	return ns.NlHandle().LinkByIndex(index)
}
var hostAddrList = func(link netlink.Link, family int) ([]netlink.Addr, error) {
	return ns.NlHandle().AddrList(link, family)
}

type egressEndpointConfig struct {
	Addr            *net.IPNet
	Addrv6          *net.IPNet
	HostIf          string
	EndpointIfindex uint32
	HostIPv4        net.IP
	HostIPv6        net.IP
	MasqueradeIPv4  bool
	MasqueradeIPv6  bool
}

type localEndpointConfig struct {
	NetworkID       string
	NetworkKey      [16]byte
	HostIf          string
	EndpointIfindex uint32
	Addr            *net.IPNet
	Addrv6          *net.IPNet
}

type ebpfPublishedPortDatapath struct {
	mu sync.Mutex

	handles                    netkitPortmapHandles
	globalLinks                []link.Link
	globalIfindices            map[int]struct{}
	parentLinks                map[string][]link.Link
	parentAttachments          map[string][]publishedPortTCXAttachment
	endpointLinks              map[string][]link.Link
	publishedEndpointIfindexV4 map[uint32]uint32
	publishedEndpointIfindexV6 map[[16]byte]uint32
}

type netkitPortmapHandles struct {
	EndpointPrimary   *ebpf.Program `ebpf:"endpoint_primary"`
	EndpointPeer      *ebpf.Program `ebpf:"endpoint_peer"`
	PortmapIngress    *ebpf.Program `ebpf:"portmap_ingress"`
	PortmapEgress     *ebpf.Program `ebpf:"portmap_egress"`
	Connect4          *ebpf.Program `ebpf:"connect4"`
	Connect6          *ebpf.Program `ebpf:"connect6"`
	Sendmsg4          *ebpf.Program `ebpf:"sendmsg4"`
	Sendmsg6          *ebpf.Program `ebpf:"sendmsg6"`
	Getpeername4      *ebpf.Program `ebpf:"getpeername4"`
	Getpeername6      *ebpf.Program `ebpf:"getpeername6"`
	EgressEndpointsV4 *ebpf.Map     `ebpf:"egress_endpoints_v4"`
	EgressEndpointsV6 *ebpf.Map     `ebpf:"egress_endpoints_v6"`
	EgressFlowsV4     *ebpf.Map     `ebpf:"egress_flows_v4"`
	EgressFlowsV6     *ebpf.Map     `ebpf:"egress_flows_v6"`
	EgressIfaces      *ebpf.Map     `ebpf:"egress_ifaces"`
	LocalSources      *ebpf.Map     `ebpf:"local_sources"`
	LocalEndpointsV4  *ebpf.Map     `ebpf:"local_endpoints_v4"`
	LocalEndpointsV6  *ebpf.Map     `ebpf:"local_endpoints_v6"`
	PublishedPortsV4  *ebpf.Map     `ebpf:"published_ports_v4"`
	PublishedPortsV6  *ebpf.Map     `ebpf:"published_ports_v6"`
	PublishedFlowsV4  *ebpf.Map     `ebpf:"published_flows_v4"`
	PublishedFlowsV6  *ebpf.Map     `ebpf:"published_flows_v6"`
	PublishedSockV4   *ebpf.Map     `ebpf:"published_sock_v4"`
	PublishedSockV6   *ebpf.Map     `ebpf:"published_sock_v6"`
	PublishedIfaces   *ebpf.Map     `ebpf:"published_ifaces"`
}

type publishedPortTCXAttachment struct {
	Ifindex int
	Attach  ebpf.AttachType
}

type publishedPortV4Key struct {
	HostIP   uint32
	HostPort uint16
	Proto    uint8
	Flags    uint8
}

type publishedPortV4Value struct {
	EndpointIP   uint32
	EndpointPort uint16
	Flags        uint16
	Ifindex      uint32
}

type publishedPortV6Key struct {
	HostIP   [16]byte
	HostPort uint16
	Proto    uint8
	Flags    uint8
}

type publishedPortV6Value struct {
	EndpointIP   [16]byte
	EndpointPort uint16
	Flags        uint16
	Ifindex      uint32
}

type publishedFlowV4Key struct {
	SrcIP   uint32
	DstIP   uint32
	SrcPort uint16
	DstPort uint16
	Proto   uint8
	Pad1    uint8
	Pad2    uint16
}

type publishedFlowV4Value struct {
	FrontendIP   uint32
	FrontendPort uint16
	Flags        uint16
	Ifindex      uint32
}

type publishedFlowV6Key struct {
	SrcIP   [16]byte
	DstIP   [16]byte
	SrcPort uint16
	DstPort uint16
	Proto   uint8
	Pad1    uint8
	Pad2    uint16
}

type publishedFlowV6Value struct {
	FrontendIP   [16]byte
	FrontendPort uint16
	Flags        uint16
	Ifindex      uint32
}

type publishedSockV4Value struct {
	FrontendIP   uint32
	BackendIP    uint32
	FrontendPort uint16
	BackendPort  uint16
	Proto        uint8
	Flags        uint8
	Pad          uint16
}

type publishedSockV6Value struct {
	FrontendIP   [16]byte
	BackendIP    [16]byte
	FrontendPort uint16
	BackendPort  uint16
	Proto        uint8
	Flags        uint8
	Pad          uint16
}

type publishedIfaceValue struct {
	Flags uint8
	Pad1  uint8
	Pad2  uint16
}

type egressEndpointV4Key struct {
	EndpointIP uint32
}

type egressEndpointV4Value struct {
	HostIP  uint32
	Flags   uint8
	Pad1    uint8
	Pad2    uint16
	Ifindex uint32
}

type egressEndpointV6Key struct {
	EndpointIP [16]byte
}

type egressEndpointV6Value struct {
	HostIP  [16]byte
	Flags   uint8
	Pad1    uint8
	Pad2    uint16
	Ifindex uint32
}

type egressFlowV4Key struct {
	SrcIP   uint32
	DstIP   uint32
	SrcPort uint16
	DstPort uint16
	Proto   uint8
	Pad1    uint8
	Pad2    uint16
}

type egressFlowV4Value struct {
	EndpointIP uint32
	Ifindex    uint32
}

type egressFlowV6Key struct {
	SrcIP   [16]byte
	DstIP   [16]byte
	SrcPort uint16
	DstPort uint16
	Proto   uint8
	Pad1    uint8
	Pad2    uint16
}

type egressFlowV6Value struct {
	EndpointIP [16]byte
	Ifindex    uint32
}

type egressIfaceValue struct {
	IPv4 uint32
	IPv6 [16]byte
}

type localSourceValue struct {
	NetworkID [16]byte
}

type localEndpointV4Key struct {
	NetworkID  [16]byte
	EndpointIP uint32
}

type localEndpointV6Key struct {
	NetworkID  [16]byte
	EndpointIP [16]byte
}

type localEndpointValue struct {
	Ifindex uint32
}

func newEBPFPublishedPortDatapath(_ context.Context, scope string) (publishedPortDatapath, error) {
	_ = scope

	if !sysinfo.New().CgroupUnified {
		return nil, classifyPublishedPortDatapathError("attach published-port host socket programs", errors.New("cgroup v2 unified mode required"))
	}

	spec, err := loadNetkitPortmap()
	if err != nil {
		return nil, fmt.Errorf("load netkit published-port bpf spec: %w", err)
	}
	if err := rewritePublishedPortConstants(spec); err != nil {
		return nil, classifyPublishedPortDatapathError("rewrite netkit published-port constants", err)
	}

	var handles netkitPortmapHandles
	if err := spec.LoadAndAssign(&handles, nil); err != nil {
		return nil, classifyPublishedPortDatapathError("load netkit published-port bpf objects", err)
	}

	dp := &ebpfPublishedPortDatapath{
		handles:                    handles,
		globalIfindices:            map[int]struct{}{},
		parentLinks:                map[string][]link.Link{},
		parentAttachments:          map[string][]publishedPortTCXAttachment{},
		endpointLinks:              map[string][]link.Link{},
		publishedEndpointIfindexV4: map[uint32]uint32{},
		publishedEndpointIfindexV6: map[[16]byte]uint32{},
	}
	defer func() {
		if err != nil {
			_ = dp.Close()
		}
	}()

	links, err := listLinks()
	if err != nil {
		return nil, fmt.Errorf("list host links for published-port datapath: %w", err)
	}

	for _, attachment := range publishedPortGlobalTCXAttachments(hostFacingLinkIndices(nil, links)) {
		if err = dp.attachGlobal(attachment.Ifindex, attachment.Attach); err != nil {
			return nil, err
		}
	}
	if err = dp.attachCgroupPrograms(); err != nil {
		return nil, err
	}

	return dp, nil
}

func publishedPortGlobalTCXAttachments(hostFacing []int) []publishedPortTCXAttachment {
	var attachments []publishedPortTCXAttachment
	for _, ifindex := range hostFacing {
		attachments = append(attachments,
			publishedPortTCXAttachment{Ifindex: ifindex, Attach: ebpf.AttachTCXIngress},
			publishedPortTCXAttachment{Ifindex: ifindex, Attach: ebpf.AttachTCXEgress},
		)
	}
	return attachments
}

func publishedPortParentTCXAttachments(parentIfindex int, bridgeSlaves []int) []publishedPortTCXAttachment {
	attachments := []publishedPortTCXAttachment{
		{Ifindex: parentIfindex, Attach: ebpf.AttachTCXIngress},
		{Ifindex: parentIfindex, Attach: ebpf.AttachTCXEgress},
	}
	for _, ifindex := range bridgeSlaves {
		attachments = append(attachments,
			publishedPortTCXAttachment{Ifindex: ifindex, Attach: ebpf.AttachTCXIngress},
			publishedPortTCXAttachment{Ifindex: ifindex, Attach: ebpf.AttachTCXEgress},
		)
	}
	return attachments
}

func publishedPortCgroupAttachTypes() []ebpf.AttachType {
	return []ebpf.AttachType{
		ebpf.AttachCGroupInet4Connect,
		ebpf.AttachCGroupInet6Connect,
		ebpf.AttachCGroupUDP4Sendmsg,
		ebpf.AttachCGroupUDP6Sendmsg,
		ebpf.AttachCgroupInet4GetPeername,
		ebpf.AttachCgroupInet6GetPeername,
	}
}

func rewritePublishedPortConstants(spec *ebpf.CollectionSpec) error {
	if spec == nil || spec.Variables["host_netns_cookie"] == nil {
		return nil
	}
	cookie, err := hostNetNSCookie()
	if err != nil {
		return fmt.Errorf("resolve host netns cookie: %w", err)
	}
	return spec.RewriteConstants(map[string]interface{}{
		"host_netns_cookie": cookie,
	})
}

func hostNetNSCookie() (uint64, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)

	return unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_NETNS_COOKIE)
}

func (d *ebpfPublishedPortDatapath) AddParent(parent string) error {
	_ = parent

	return nil
}

func (d *ebpfPublishedPortDatapath) RemoveParent(parent string) error {
	_ = parent

	return nil
}

func (d *ebpfPublishedPortDatapath) addBridgeAttachments(parent string) error {
	parentLink, err := ns.NlHandle().LinkByName(parent)
	if err != nil {
		return fmt.Errorf("resolve published-port parent %q: %w", parent, err)
	}
	links, err := listLinks()
	if err != nil {
		return fmt.Errorf("list published-port parent links for %q: %w", parent, err)
	}
	attachments := publishedPortParentTCXAttachments(parentLink.Attrs().Index, bridgeSlaveLinkIndices(parentLink, links))

	d.mu.Lock()
	defer d.mu.Unlock()

	oldLinks := d.parentLinks[parent]
	oldAttachments := d.parentAttachments[parent]
	var attached []link.Link
	for _, attachment := range attachments {
		lnk, err := d.attach(attachment.Ifindex, attachment.Attach)
		if err != nil {
			closeLinks(attached)
			return err
		}
		attached = append(attached, lnk)
	}
	if err := d.setInterfaceRoles(attachments, false); err != nil {
		_ = closeLinks(attached)
		return err
	}
	d.parentLinks[parent] = attached
	d.parentAttachments[parent] = attachments
	return errors.Join(closeLinks(oldLinks), d.clearRemovedParentRoles(oldAttachments, attachments))
}

func (d *ebpfPublishedPortDatapath) attachGlobal(ifindex int, attachType ebpf.AttachType) error {
	lnk, err := d.attach(ifindex, attachType)
	if err != nil {
		return err
	}
	d.globalLinks = append(d.globalLinks, lnk)
	if err := d.setInterfaceRole(ifindex, true); err != nil {
		return err
	}
	if _, ok := d.globalIfindices[ifindex]; !ok {
		if err := d.setEgressInterface(ifindex); err != nil {
			return err
		}
	}
	d.globalIfindices[ifindex] = struct{}{}
	return nil
}

func (d *ebpfPublishedPortDatapath) attachCgroupPrograms() error {
	for _, attachType := range publishedPortCgroupAttachTypes() {
		program := d.programForAttachType(attachType)
		if program == nil {
			return fmt.Errorf("program for %s is not initialized", attachType)
		}
		lnk, err := attachCgroup(link.CgroupOptions{
			Path:    publishedPortCgroupPath,
			Attach:  attachType,
			Program: program,
		})
		if err != nil {
			return classifyPublishedPortDatapathError("attach published-port host socket programs", err)
		}
		d.globalLinks = append(d.globalLinks, lnk)
	}
	return nil
}

func (d *ebpfPublishedPortDatapath) programForAttachType(attachType ebpf.AttachType) *ebpf.Program {
	switch attachType {
	case ebpf.AttachCGroupInet4Connect:
		return d.handles.Connect4
	case ebpf.AttachCGroupInet6Connect:
		return d.handles.Connect6
	case ebpf.AttachCGroupUDP4Sendmsg:
		return d.handles.Sendmsg4
	case ebpf.AttachCGroupUDP6Sendmsg:
		return d.handles.Sendmsg6
	case ebpf.AttachCgroupInet4GetPeername:
		return d.handles.Getpeername4
	case ebpf.AttachCgroupInet6GetPeername:
		return d.handles.Getpeername6
	default:
		return nil
	}
}

func (d *ebpfPublishedPortDatapath) attach(ifindex int, attachType ebpf.AttachType) (link.Link, error) {
	program := d.handles.PortmapIngress
	if attachType == ebpf.AttachTCXEgress {
		program = d.handles.PortmapEgress
	}
	lnk, err := attachTCX(link.TCXOptions{
		Interface: ifindex,
		Program:   program,
		Attach:    attachType,
	})
	if err != nil {
		return nil, classifyPublishedPortDatapathError(
			fmt.Sprintf("attach netkit published-port tcx program to ifindex %d", ifindex),
			err,
		)
	}
	return lnk, nil
}

func (d *ebpfPublishedPortDatapath) AttachEndpoint(hostIf string) error {
	if strings.TrimSpace(hostIf) == "" {
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if _, ok := d.endpointLinks[hostIf]; ok {
		return nil
	}

	hostLink, err := hostLinkByName(hostIf)
	if err != nil {
		return fmt.Errorf("resolve netkit primary %q: %w", hostIf, err)
	}
	ifindex := hostLink.Attrs().Index

	primary, err := attachNetkit(link.NetkitOptions{
		Interface: ifindex,
		Program:   d.handles.EndpointPrimary,
		Attach:    ebpf.AttachNetkitPrimary,
	})
	if err != nil {
		return classifyEndpointNetkitDatapathError(
			fmt.Sprintf("attach netkit primary program to %s", hostIf),
			err,
		)
	}

	peer, err := attachNetkit(link.NetkitOptions{
		Interface: ifindex,
		Program:   d.handles.EndpointPeer,
		Attach:    ebpf.AttachNetkitPeer,
	})
	if err != nil {
		_ = primary.Close()
		return classifyEndpointNetkitDatapathError(
			fmt.Sprintf("attach netkit peer program to %s", hostIf),
			err,
		)
	}

	d.endpointLinks[hostIf] = []link.Link{primary, peer}
	return nil
}

func (d *ebpfPublishedPortDatapath) DetachEndpoint(hostIf string) error {
	if strings.TrimSpace(hostIf) == "" {
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	links := d.endpointLinks[hostIf]
	delete(d.endpointLinks, hostIf)
	return closeLinks(links)
}

func (d *ebpfPublishedPortDatapath) AddBindings(bindings []portmapperapi.PortBinding) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	var errs []error
	for _, binding := range bindings {
		if ip4 := binding.HostIP.To4(); ip4 != nil {
			key, value, err := publishedPortEntryV4(binding)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if ifindex, ok := d.publishedEndpointIfindexV4[value.EndpointIP]; ok {
				value.Ifindex = ifindex
			}
			if err := d.handles.PublishedPortsV4.Put(key, value); err != nil {
				errs = append(errs, fmt.Errorf("program published-port ipv4 map for %s: %w", binding, err))
			}
			continue
		}

		key, value, err := publishedPortEntryV6(binding)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if ifindex, ok := d.publishedEndpointIfindexV6[value.EndpointIP]; ok {
			value.Ifindex = ifindex
		}
		if err := d.handles.PublishedPortsV6.Put(key, value); err != nil {
			errs = append(errs, fmt.Errorf("program published-port ipv6 map for %s: %w", binding, err))
		}
	}
	return errors.Join(errs...)
}

func (d *ebpfPublishedPortDatapath) AddPublishedEndpoint(ep publishedEndpointConfig) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if strings.TrimSpace(ep.HostIf) == "" {
		return fmt.Errorf("published endpoint host interface is empty")
	}
	link, err := hostLinkByName(ep.HostIf)
	if err != nil {
		return fmt.Errorf("resolve published endpoint host interface %q: %w", ep.HostIf, err)
	}
	ifindex := uint32(link.Attrs().Index)

	var errs []error
	if ep.Addr != nil {
		key, err := publishedEndpointKeyV4(ep.Addr)
		if err != nil {
			errs = append(errs, err)
		} else {
			d.publishedEndpointIfindexV4[key] = ifindex
		}
	}
	if ep.Addrv6 != nil {
		key, err := publishedEndpointKeyV6(ep.Addrv6)
		if err != nil {
			errs = append(errs, err)
		} else {
			d.publishedEndpointIfindexV6[key] = ifindex
		}
	}
	return errors.Join(errs...)
}

func (d *ebpfPublishedPortDatapath) RemovePublishedEndpoint(ep publishedEndpointConfig) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	var errs []error
	if ep.Addr != nil {
		key, err := publishedEndpointKeyV4(ep.Addr)
		if err != nil {
			errs = append(errs, err)
		} else {
			delete(d.publishedEndpointIfindexV4, key)
		}
	}
	if ep.Addrv6 != nil {
		key, err := publishedEndpointKeyV6(ep.Addrv6)
		if err != nil {
			errs = append(errs, err)
		} else {
			delete(d.publishedEndpointIfindexV6, key)
		}
	}
	return errors.Join(errs...)
}

func (d *ebpfPublishedPortDatapath) UpsertEgressEndpoint(ep egressEndpointConfig) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if strings.TrimSpace(ep.HostIf) != "" {
		link, err := hostLinkByName(ep.HostIf)
		if err != nil {
			return fmt.Errorf("resolve egress endpoint host interface %q: %w", ep.HostIf, err)
		}
		ep.EndpointIfindex = uint32(link.Attrs().Index)
	}

	var errs []error
	if ep.Addr != nil {
		key, value, ok, err := egressEndpointEntryV4(ep)
		if err != nil {
			errs = append(errs, err)
		} else if ok {
			if err := d.handles.EgressEndpointsV4.Put(key, value); err != nil {
				errs = append(errs, fmt.Errorf("program egress ipv4 endpoint map for %s: %w", ep.Addr, err))
			}
		}
	}
	if ep.Addrv6 != nil {
		key, value, ok, err := egressEndpointEntryV6(ep)
		if err != nil {
			errs = append(errs, err)
		} else if ok {
			if err := d.handles.EgressEndpointsV6.Put(key, value); err != nil {
				errs = append(errs, fmt.Errorf("program egress ipv6 endpoint map for %s: %w", ep.Addrv6, err))
			}
		}
	}
	return errors.Join(errs...)
}

func (d *ebpfPublishedPortDatapath) RemoveEgressEndpoint(ep egressEndpointConfig) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	var errs []error
	if ep.Addr != nil {
		key, err := egressEndpointKeyV4(ep.Addr)
		if err != nil {
			errs = append(errs, err)
		} else {
			if err := d.handles.EgressEndpointsV4.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				errs = append(errs, fmt.Errorf("delete egress ipv4 endpoint map entry for %s: %w", ep.Addr, err))
			}
			errs = append(errs, d.removeEgressStateV4(ep.Addr)...)
		}
	}
	if ep.Addrv6 != nil {
		key, err := egressEndpointKeyV6(ep.Addrv6)
		if err != nil {
			errs = append(errs, err)
		} else {
			if err := d.handles.EgressEndpointsV6.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				errs = append(errs, fmt.Errorf("delete egress ipv6 endpoint map entry for %s: %w", ep.Addrv6, err))
			}
			errs = append(errs, d.removeEgressStateV6(ep.Addrv6)...)
		}
	}
	return errors.Join(errs...)
}

func (d *ebpfPublishedPortDatapath) UpsertLocalEndpoint(ep localEndpointConfig) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	return upsertLocalEndpoint(d.handles.LocalSources, d.handles.LocalEndpointsV4, d.handles.LocalEndpointsV6, ep)
}

func (d *ebpfPublishedPortDatapath) RemoveLocalEndpoint(ep localEndpointConfig) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	return removeLocalEndpoint(d.handles.LocalSources, d.handles.LocalEndpointsV4, d.handles.LocalEndpointsV6, ep)
}

func (d *ebpfPublishedPortDatapath) RemoveBindings(bindings []portmapperapi.PortBinding) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	var errs []error
	for _, binding := range bindings {
		if ip4 := binding.HostIP.To4(); ip4 != nil {
			key, err := publishedPortKeyV4FromBinding(binding)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if err := d.handles.PublishedPortsV4.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				errs = append(errs, fmt.Errorf("delete published-port ipv4 map entry for %s: %w", binding, err))
			}
		} else {
			key, err := publishedPortKeyV6FromBinding(binding)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if err := d.handles.PublishedPortsV6.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				errs = append(errs, fmt.Errorf("delete published-port ipv6 map entry for %s: %w", binding, err))
			}
		}

		errs = append(errs, d.removeBindingState(binding)...)
	}
	return errors.Join(errs...)
}

func (d *ebpfPublishedPortDatapath) removeEgressStateV4(addr *net.IPNet) []error {
	var errs []error

	ip4 := addr.IP.To4()
	if ip4 == nil {
		return []error{fmt.Errorf("invalid ipv4 egress state cleanup for %v", addr)}
	}
	endpointKey := binary.BigEndian.Uint32(ip4)

	var deletes []egressFlowV4Key
	iter := d.handles.EgressFlowsV4.Iterate()
	var key egressFlowV4Key
	var value egressFlowV4Value
	for iter.Next(&key, &value) {
		if value.EndpointIP == endpointKey {
			deletes = append(deletes, key)
		}
	}
	if err := iter.Err(); err != nil {
		errs = append(errs, fmt.Errorf("iterate egress ipv4 flow state for %s: %w", addr, err))
	}
	for _, key := range deletes {
		if err := d.handles.EgressFlowsV4.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("delete egress ipv4 flow state for %s: %w", addr, err))
		}
	}
	return errs
}

func (d *ebpfPublishedPortDatapath) removeEgressStateV6(addr *net.IPNet) []error {
	var errs []error

	ip6 := addr.IP.To16()
	if ip6 == nil || addr.IP.To4() != nil {
		return []error{fmt.Errorf("invalid ipv6 egress state cleanup for %v", addr)}
	}
	var endpointKey [16]byte
	copy(endpointKey[:], ip6)

	var deletes []egressFlowV6Key
	iter := d.handles.EgressFlowsV6.Iterate()
	var key egressFlowV6Key
	var value egressFlowV6Value
	for iter.Next(&key, &value) {
		if value.EndpointIP == endpointKey {
			deletes = append(deletes, key)
		}
	}
	if err := iter.Err(); err != nil {
		errs = append(errs, fmt.Errorf("iterate egress ipv6 flow state for %s: %w", addr, err))
	}
	for _, key := range deletes {
		if err := d.handles.EgressFlowsV6.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("delete egress ipv6 flow state for %s: %w", addr, err))
		}
	}
	return errs
}

func (d *ebpfPublishedPortDatapath) removeBindingState(binding portmapperapi.PortBinding) []error {
	if binding.HostIP.To4() != nil {
		return d.removeBindingStateV4(binding)
	}
	return d.removeBindingStateV6(binding)
}

func (d *ebpfPublishedPortDatapath) removeBindingStateV4(binding portmapperapi.PortBinding) []error {
	var errs []error

	hostIP := binding.HostIP.To4()
	endpointIP := binding.IP.To4()
	if hostIP == nil || endpointIP == nil {
		return []error{fmt.Errorf("invalid ipv4 binding state cleanup for %s", binding)}
	}
	hostKey := binary.BigEndian.Uint32(hostIP)
	endpointKey := binary.BigEndian.Uint32(endpointIP)

	var flowDeletes []publishedFlowV4Key
	iter := d.handles.PublishedFlowsV4.Iterate()
	var flowKey publishedFlowV4Key
	var flowValue publishedFlowV4Value
	for iter.Next(&flowKey, &flowValue) {
		if flowKey.Proto != uint8(binding.Proto) || flowKey.SrcIP != endpointKey || flowKey.SrcPort != binding.Port {
			continue
		}
		if flowValue.FrontendPort != binding.HostPort || flowValue.Flags != uint16(bindingFlags(binding)) {
			continue
		}
		if !binding.HostIP.IsUnspecified() && flowValue.FrontendIP != hostKey {
			continue
		}
		flowDeletes = append(flowDeletes, flowKey)
	}
	if err := iter.Err(); err != nil {
		errs = append(errs, fmt.Errorf("iterate published-port ipv4 flow state for %s: %w", binding, err))
	}
	for _, key := range flowDeletes {
		if err := d.handles.PublishedFlowsV4.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("delete published-port ipv4 flow state for %s: %w", binding, err))
		}
	}

	var sockDeletes []uint64
	sockIter := d.handles.PublishedSockV4.Iterate()
	var sockKey uint64
	var sockValue publishedSockV4Value
	for sockIter.Next(&sockKey, &sockValue) {
		if sockValue.Proto != uint8(binding.Proto) || sockValue.BackendIP != endpointKey || sockValue.BackendPort != binding.Port {
			continue
		}
		if sockValue.FrontendPort != binding.HostPort || uint16(sockValue.Flags) != uint16(bindingFlags(binding)) {
			continue
		}
		if !binding.HostIP.IsUnspecified() && sockValue.FrontendIP != hostKey {
			continue
		}
		sockDeletes = append(sockDeletes, sockKey)
	}
	if err := sockIter.Err(); err != nil {
		errs = append(errs, fmt.Errorf("iterate published-port ipv4 socket state for %s: %w", binding, err))
	}
	for _, key := range sockDeletes {
		if err := d.handles.PublishedSockV4.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("delete published-port ipv4 socket state for %s: %w", binding, err))
		}
	}

	return errs
}

func (d *ebpfPublishedPortDatapath) removeBindingStateV6(binding portmapperapi.PortBinding) []error {
	var errs []error

	hostIP := binding.HostIP.To16()
	endpointIP := binding.IP.To16()
	if hostIP == nil || endpointIP == nil || binding.HostIP.To4() != nil || binding.IP.To4() != nil {
		return []error{fmt.Errorf("invalid ipv6 binding state cleanup for %s", binding)}
	}

	var hostKey [16]byte
	copy(hostKey[:], hostIP)
	var endpointKey [16]byte
	copy(endpointKey[:], endpointIP)

	var flowDeletes []publishedFlowV6Key
	iter := d.handles.PublishedFlowsV6.Iterate()
	var flowKey publishedFlowV6Key
	var flowValue publishedFlowV6Value
	for iter.Next(&flowKey, &flowValue) {
		if flowKey.Proto != uint8(binding.Proto) || flowKey.SrcIP != endpointKey || flowKey.SrcPort != binding.Port {
			continue
		}
		if flowValue.FrontendPort != binding.HostPort || flowValue.Flags != uint16(bindingFlags(binding)) {
			continue
		}
		if !binding.HostIP.IsUnspecified() && flowValue.FrontendIP != hostKey {
			continue
		}
		flowDeletes = append(flowDeletes, flowKey)
	}
	if err := iter.Err(); err != nil {
		errs = append(errs, fmt.Errorf("iterate published-port ipv6 flow state for %s: %w", binding, err))
	}
	for _, key := range flowDeletes {
		if err := d.handles.PublishedFlowsV6.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("delete published-port ipv6 flow state for %s: %w", binding, err))
		}
	}

	var sockDeletes []uint64
	sockIter := d.handles.PublishedSockV6.Iterate()
	var sockKey uint64
	var sockValue publishedSockV6Value
	for sockIter.Next(&sockKey, &sockValue) {
		if sockValue.Proto != uint8(binding.Proto) || sockValue.BackendIP != endpointKey || sockValue.BackendPort != binding.Port {
			continue
		}
		if sockValue.FrontendPort != binding.HostPort || uint16(sockValue.Flags) != uint16(bindingFlags(binding)) {
			continue
		}
		if !binding.HostIP.IsUnspecified() && sockValue.FrontendIP != hostKey {
			continue
		}
		sockDeletes = append(sockDeletes, sockKey)
	}
	if err := sockIter.Err(); err != nil {
		errs = append(errs, fmt.Errorf("iterate published-port ipv6 socket state for %s: %w", binding, err))
	}
	for _, key := range sockDeletes {
		if err := d.handles.PublishedSockV6.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("delete published-port ipv6 socket state for %s: %w", binding, err))
		}
	}

	return errs
}

func (d *ebpfPublishedPortDatapath) setInterfaceRoles(attachments []publishedPortTCXAttachment, redirect bool) error {
	seen := map[int]struct{}{}
	var errs []error
	for _, attachment := range attachments {
		if _, ok := seen[attachment.Ifindex]; ok {
			continue
		}
		seen[attachment.Ifindex] = struct{}{}
		errs = append(errs, d.setInterfaceRole(attachment.Ifindex, redirect))
	}
	return errors.Join(errs...)
}

func (d *ebpfPublishedPortDatapath) clearInterfaceRoles(attachments []publishedPortTCXAttachment) error {
	seen := map[int]struct{}{}
	var errs []error
	for _, attachment := range attachments {
		if _, ok := seen[attachment.Ifindex]; ok {
			continue
		}
		seen[attachment.Ifindex] = struct{}{}
		errs = append(errs, d.clearInterfaceRole(attachment.Ifindex))
	}
	return errors.Join(errs...)
}

func (d *ebpfPublishedPortDatapath) clearRemovedParentRoles(previous, current []publishedPortTCXAttachment) error {
	currentIfindices := map[int]struct{}{}
	for _, attachment := range current {
		currentIfindices[attachment.Ifindex] = struct{}{}
	}

	seen := map[int]struct{}{}
	var errs []error
	for _, attachment := range previous {
		if _, ok := currentIfindices[attachment.Ifindex]; ok {
			continue
		}
		if _, ok := seen[attachment.Ifindex]; ok {
			continue
		}
		seen[attachment.Ifindex] = struct{}{}
		errs = append(errs, d.clearInterfaceRole(attachment.Ifindex))
	}
	return errors.Join(errs...)
}

func (d *ebpfPublishedPortDatapath) setEgressInterface(ifindex int) error {
	if d.handles.EgressIfaces == nil {
		return nil
	}

	link, err := hostLinkByIndex(ifindex)
	if err != nil {
		return fmt.Errorf("resolve host-facing link %d for egress nat: %w", ifindex, err)
	}

	addrs4, err := hostAddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("list ipv4 addresses for %s: %w", link.Attrs().Name, err)
	}
	addrs6, err := hostAddrList(link, netlink.FAMILY_V6)
	if err != nil {
		return fmt.Errorf("list ipv6 addresses for %s: %w", link.Attrs().Name, err)
	}

	value := egressIfaceValue{}
	for _, addr := range addrs4 {
		if addr.IP == nil || addr.IP.IsLoopback() || addr.IP.To4() == nil {
			continue
		}
		value.IPv4 = binary.BigEndian.Uint32(addr.IP.To4())
		break
	}
	for _, addr := range addrs6 {
		if addr.IP == nil || addr.IP.To16() == nil || addr.IP.To4() != nil || addr.IP.IsLoopback() {
			continue
		}
		copy(value.IPv6[:], addr.IP.To16())
		break
	}
	return d.handles.EgressIfaces.Put(uint32(ifindex), value)
}

func (d *ebpfPublishedPortDatapath) setInterfaceRole(ifindex int, redirect bool) error {
	if d.handles.PublishedIfaces == nil {
		return nil
	}
	value := publishedIfaceValue{}
	if redirect {
		value.Flags = publishedIfaceFlagRedirectReply
	}
	return d.handles.PublishedIfaces.Put(uint32(ifindex), value)
}

func (d *ebpfPublishedPortDatapath) clearInterfaceRole(ifindex int) error {
	if d.handles.PublishedIfaces == nil {
		return nil
	}
	if err := d.handles.PublishedIfaces.Delete(uint32(ifindex)); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	return nil
}

func (d *ebpfPublishedPortDatapath) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	var errs []error
	for parent := range d.parentLinks {
		errs = append(errs, closeLinks(d.parentLinks[parent]))
		errs = append(errs, d.clearInterfaceRoles(d.parentAttachments[parent]))
	}
	d.parentLinks = map[string][]link.Link{}
	d.parentAttachments = map[string][]publishedPortTCXAttachment{}
	for hostIf, links := range d.endpointLinks {
		errs = append(errs, closeLinks(links))
		delete(d.endpointLinks, hostIf)
	}
	errs = append(errs, closeLinks(d.globalLinks))
	d.globalLinks = nil
	for ifindex := range d.globalIfindices {
		errs = append(errs, d.clearInterfaceRole(ifindex))
		if d.handles.EgressIfaces != nil {
			if err := d.handles.EgressIfaces.Delete(uint32(ifindex)); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				errs = append(errs, err)
			}
		}
	}
	d.globalIfindices = map[int]struct{}{}
	errs = append(errs, d.handles.Close())
	return errors.Join(errs...)
}

func (h *netkitPortmapHandles) Close() error {
	return errors.Join(
		closeMap(h.LocalEndpointsV6),
		closeMap(h.LocalEndpointsV4),
		closeMap(h.LocalSources),
		closeMap(h.EgressIfaces),
		closeMap(h.EgressFlowsV6),
		closeMap(h.EgressFlowsV4),
		closeMap(h.EgressEndpointsV6),
		closeMap(h.EgressEndpointsV4),
		closeMap(h.PublishedSockV6),
		closeMap(h.PublishedSockV4),
		closeMap(h.PublishedFlowsV6),
		closeMap(h.PublishedFlowsV4),
		closeMap(h.PublishedIfaces),
		closeMap(h.PublishedPortsV4),
		closeMap(h.PublishedPortsV6),
		closeProgram(h.Getpeername6),
		closeProgram(h.Getpeername4),
		closeProgram(h.Sendmsg6),
		closeProgram(h.Sendmsg4),
		closeProgram(h.Connect6),
		closeProgram(h.Connect4),
		closeProgram(h.PortmapIngress),
		closeProgram(h.PortmapEgress),
		closeProgram(h.EndpointPrimary),
		closeProgram(h.EndpointPeer),
	)
}

func closeLinks(links []link.Link) error {
	var errs []error
	for _, lnk := range links {
		errs = append(errs, lnk.Close())
	}
	return errors.Join(errs...)
}

func classifyPublishedPortDatapathError(op string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ebpf.ErrNotSupported) || errors.Is(err, link.ErrNotSupported) || looksLikeUnsupportedDatapathError(err) {
		return errdefs.NotImplemented(fmt.Errorf("netkit pure eBPF port mapping unsupported on this kernel during %s: %w", op, err))
	}
	return fmt.Errorf("%s: %w", op, err)
}

func looksLikeUnsupportedDatapathError(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not supported") ||
		strings.Contains(msg, "unknown func") ||
		strings.Contains(msg, "kfunc") ||
		strings.Contains(msg, "__ksym") ||
		strings.Contains(msg, "btf") ||
		strings.Contains(msg, "cgroup v2 unified mode required") ||
		strings.Contains(msg, "struct nf_conn") ||
		strings.Contains(msg, "invalid func")
}

func closeMap(m *ebpf.Map) error {
	if m == nil {
		return nil
	}
	return m.Close()
}

func closeProgram(p *ebpf.Program) error {
	if p == nil {
		return nil
	}
	return p.Close()
}

func publishedPortEntryV4(binding portmapperapi.PortBinding) (publishedPortV4Key, publishedPortV4Value, error) {
	key, err := publishedPortKeyV4FromBinding(binding)
	if err != nil {
		return publishedPortV4Key{}, publishedPortV4Value{}, err
	}
	containerIP := binding.IP.To4()
	if containerIP == nil {
		return publishedPortV4Key{}, publishedPortV4Value{}, fmt.Errorf("invalid ipv4 endpoint address for %s", binding)
	}
	return key, publishedPortV4Value{
		EndpointIP:   binary.BigEndian.Uint32(containerIP),
		EndpointPort: binding.Port,
		Flags:        uint16(bindingFlags(binding)),
	}, nil
}

func publishedEndpointKeyV4(addr *net.IPNet) (uint32, error) {
	if addr == nil || addr.IP == nil {
		return 0, fmt.Errorf("missing ipv4 published endpoint address")
	}
	ip4 := addr.IP.To4()
	if ip4 == nil {
		return 0, fmt.Errorf("invalid ipv4 published endpoint address %s", addr)
	}
	return binary.BigEndian.Uint32(ip4), nil
}

func egressEndpointKeyV4(addr *net.IPNet) (egressEndpointV4Key, error) {
	if addr == nil || addr.IP == nil {
		return egressEndpointV4Key{}, fmt.Errorf("missing ipv4 endpoint address")
	}
	ip4 := addr.IP.To4()
	if ip4 == nil {
		return egressEndpointV4Key{}, fmt.Errorf("invalid ipv4 endpoint address %s", addr)
	}
	return egressEndpointV4Key{EndpointIP: binary.BigEndian.Uint32(ip4)}, nil
}

func egressEndpointEntryV4(ep egressEndpointConfig) (egressEndpointV4Key, egressEndpointV4Value, bool, error) {
	if ep.Addr == nil || ep.Addr.IP == nil {
		return egressEndpointV4Key{}, egressEndpointV4Value{}, false, nil
	}
	key, err := egressEndpointKeyV4(ep.Addr)
	if err != nil {
		return egressEndpointV4Key{}, egressEndpointV4Value{}, false, err
	}
	if !ep.MasqueradeIPv4 && ep.HostIPv4 == nil {
		return key, egressEndpointV4Value{}, false, nil
	}
	value := egressEndpointV4Value{Ifindex: ep.EndpointIfindex}
	if ep.MasqueradeIPv4 {
		value.Flags = egressEndpointFlagMasquerade
	} else if ip4 := ep.HostIPv4.To4(); ip4 != nil {
		value.HostIP = binary.BigEndian.Uint32(ip4)
	} else {
		return egressEndpointV4Key{}, egressEndpointV4Value{}, false, fmt.Errorf("invalid ipv4 snat address %v", ep.HostIPv4)
	}
	return key, value, true, nil
}

func egressEndpointKeyV6(addr *net.IPNet) (egressEndpointV6Key, error) {
	if addr == nil || addr.IP == nil {
		return egressEndpointV6Key{}, fmt.Errorf("missing ipv6 endpoint address")
	}
	ip6 := addr.IP.To16()
	if ip6 == nil || addr.IP.To4() != nil {
		return egressEndpointV6Key{}, fmt.Errorf("invalid ipv6 endpoint address %s", addr)
	}
	var key egressEndpointV6Key
	copy(key.EndpointIP[:], ip6)
	return key, nil
}

func egressEndpointEntryV6(ep egressEndpointConfig) (egressEndpointV6Key, egressEndpointV6Value, bool, error) {
	if ep.Addrv6 == nil || ep.Addrv6.IP == nil {
		return egressEndpointV6Key{}, egressEndpointV6Value{}, false, nil
	}
	key, err := egressEndpointKeyV6(ep.Addrv6)
	if err != nil {
		return egressEndpointV6Key{}, egressEndpointV6Value{}, false, err
	}
	if !ep.MasqueradeIPv6 && ep.HostIPv6 == nil {
		return key, egressEndpointV6Value{}, false, nil
	}
	value := egressEndpointV6Value{Ifindex: ep.EndpointIfindex}
	if ep.MasqueradeIPv6 {
		value.Flags = egressEndpointFlagMasquerade
	} else if ip6 := ep.HostIPv6.To16(); ip6 != nil && ep.HostIPv6.To4() == nil {
		copy(value.HostIP[:], ip6)
	} else {
		return egressEndpointV6Key{}, egressEndpointV6Value{}, false, fmt.Errorf("invalid ipv6 snat address %v", ep.HostIPv6)
	}
	return key, value, true, nil
}

func localEndpointConfigForEndpoint(ep *endpoint) (localEndpointConfig, bool) {
	if ep == nil || strings.TrimSpace(ep.nid) == "" || strings.TrimSpace(ep.hostIf) == "" {
		return localEndpointConfig{}, false
	}
	key := sha256.Sum256([]byte(ep.nid))
	config := localEndpointConfig{
		NetworkID: ep.nid,
		HostIf:    ep.hostIf,
		Addr:      cloneIPNet(ep.addr),
		Addrv6:    cloneIPNet(ep.addrv6),
	}
	copy(config.NetworkKey[:], key[:16])
	if config.Addr == nil && config.Addrv6 == nil {
		return localEndpointConfig{}, false
	}
	return config, true
}

func upsertLocalEndpoint(sources, endpoints4, endpoints6 *ebpf.Map, ep localEndpointConfig) error {
	if sources == nil || endpoints4 == nil || endpoints6 == nil {
		return nil
	}
	if strings.TrimSpace(ep.HostIf) != "" {
		link, err := hostLinkByName(ep.HostIf)
		if err != nil {
			return fmt.Errorf("resolve local endpoint host interface %q: %w", ep.HostIf, err)
		}
		ep.EndpointIfindex = uint32(link.Attrs().Index)
	}
	if ep.EndpointIfindex == 0 {
		return fmt.Errorf("missing local endpoint ifindex for %s", ep.HostIf)
	}

	var errs []error
	source := localSourceValue{NetworkID: ep.NetworkKey}
	if err := sources.Put(ep.EndpointIfindex, source); err != nil {
		errs = append(errs, fmt.Errorf("program local source map for %s: %w", ep.HostIf, err))
	}
	if ep.Addr != nil {
		key, value, err := localEndpointEntryV4(ep)
		if err != nil {
			errs = append(errs, err)
		} else if err := endpoints4.Put(key, value); err != nil {
			errs = append(errs, fmt.Errorf("program local ipv4 endpoint map for %s: %w", ep.Addr, err))
		}
	}
	if ep.Addrv6 != nil {
		key, value, err := localEndpointEntryV6(ep)
		if err != nil {
			errs = append(errs, err)
		} else if err := endpoints6.Put(key, value); err != nil {
			errs = append(errs, fmt.Errorf("program local ipv6 endpoint map for %s: %w", ep.Addrv6, err))
		}
	}
	return errors.Join(errs...)
}

func removeLocalEndpoint(sources, endpoints4, endpoints6 *ebpf.Map, ep localEndpointConfig) error {
	if sources == nil || endpoints4 == nil || endpoints6 == nil {
		return nil
	}
	if strings.TrimSpace(ep.HostIf) != "" && ep.EndpointIfindex == 0 {
		if link, err := hostLinkByName(ep.HostIf); err == nil {
			ep.EndpointIfindex = uint32(link.Attrs().Index)
		}
	}

	var errs []error
	if ep.EndpointIfindex != 0 {
		if err := sources.Delete(ep.EndpointIfindex); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("delete local source map entry for %s: %w", ep.HostIf, err))
		}
	}
	if ep.Addr != nil {
		key, _, err := localEndpointEntryV4(ep)
		if err != nil {
			errs = append(errs, err)
		} else if err := endpoints4.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("delete local ipv4 endpoint map entry for %s: %w", ep.Addr, err))
		}
	}
	if ep.Addrv6 != nil {
		key, _, err := localEndpointEntryV6(ep)
		if err != nil {
			errs = append(errs, err)
		} else if err := endpoints6.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("delete local ipv6 endpoint map entry for %s: %w", ep.Addrv6, err))
		}
	}
	return errors.Join(errs...)
}

func localEndpointEntryV4(ep localEndpointConfig) (localEndpointV4Key, localEndpointValue, error) {
	if ep.Addr == nil || ep.Addr.IP == nil {
		return localEndpointV4Key{}, localEndpointValue{}, fmt.Errorf("missing ipv4 local endpoint address")
	}
	ip4 := ep.Addr.IP.To4()
	if ip4 == nil {
		return localEndpointV4Key{}, localEndpointValue{}, fmt.Errorf("invalid ipv4 local endpoint address %s", ep.Addr)
	}
	return localEndpointV4Key{
		NetworkID:  ep.NetworkKey,
		EndpointIP: binary.BigEndian.Uint32(ip4),
	}, localEndpointValue{Ifindex: ep.EndpointIfindex}, nil
}

func localEndpointEntryV6(ep localEndpointConfig) (localEndpointV6Key, localEndpointValue, error) {
	if ep.Addrv6 == nil || ep.Addrv6.IP == nil {
		return localEndpointV6Key{}, localEndpointValue{}, fmt.Errorf("missing ipv6 local endpoint address")
	}
	ip6 := ep.Addrv6.IP.To16()
	if ip6 == nil || ep.Addrv6.IP.To4() != nil {
		return localEndpointV6Key{}, localEndpointValue{}, fmt.Errorf("invalid ipv6 local endpoint address %s", ep.Addrv6)
	}
	key := localEndpointV6Key{NetworkID: ep.NetworkKey}
	copy(key.EndpointIP[:], ip6)
	return key, localEndpointValue{Ifindex: ep.EndpointIfindex}, nil
}

func publishedPortEntryV6(binding portmapperapi.PortBinding) (publishedPortV6Key, publishedPortV6Value, error) {
	key, err := publishedPortKeyV6FromBinding(binding)
	if err != nil {
		return publishedPortV6Key{}, publishedPortV6Value{}, err
	}
	containerIP := binding.IP.To16()
	if containerIP == nil || binding.IP.To4() != nil {
		return publishedPortV6Key{}, publishedPortV6Value{}, fmt.Errorf("invalid ipv6 endpoint address for %s", binding)
	}
	var endpoint [16]byte
	copy(endpoint[:], containerIP)
	return key, publishedPortV6Value{
		EndpointIP:   endpoint,
		EndpointPort: binding.Port,
		Flags:        uint16(bindingFlags(binding)),
	}, nil
}

func publishedEndpointKeyV6(addr *net.IPNet) ([16]byte, error) {
	if addr == nil || addr.IP == nil {
		return [16]byte{}, fmt.Errorf("missing ipv6 published endpoint address")
	}
	ip6 := addr.IP.To16()
	if ip6 == nil || addr.IP.To4() != nil {
		return [16]byte{}, fmt.Errorf("invalid ipv6 published endpoint address %s", addr)
	}
	var key [16]byte
	copy(key[:], ip6)
	return key, nil
}

func publishedPortKeyV4FromBinding(binding portmapperapi.PortBinding) (publishedPortV4Key, error) {
	hostIP := binding.HostIP.To4()
	if hostIP == nil {
		return publishedPortV4Key{}, fmt.Errorf("invalid ipv4 host address for %s", binding)
	}
	return publishedPortV4Key{
		HostIP:   binary.BigEndian.Uint32(hostIP),
		HostPort: binding.HostPort,
		Proto:    uint8(binding.Proto),
		Flags:    bindingFlags(binding),
	}, nil
}

func publishedPortKeyV6FromBinding(binding portmapperapi.PortBinding) (publishedPortV6Key, error) {
	hostIP := binding.HostIP.To16()
	if hostIP == nil || binding.HostIP.To4() != nil {
		return publishedPortV6Key{}, fmt.Errorf("invalid ipv6 host address for %s", binding)
	}
	var encoded [16]byte
	copy(encoded[:], hostIP)
	return publishedPortV6Key{
		HostIP:   encoded,
		HostPort: binding.HostPort,
		Proto:    uint8(binding.Proto),
		Flags:    bindingFlags(binding),
	}, nil
}

func bindingFlags(binding portmapperapi.PortBinding) uint8 {
	if isLoopbackIP(binding.HostIP) {
		return publishedPortFlagLoopbackOnly
	}
	return 0
}

func isLoopbackIP(ip net.IP) bool {
	return ip != nil && ip.IsLoopback()
}

func hostFacingLinkIndices(parent netlink.Link, links []netlink.Link) []int {
	var parentIndex int
	if parent != nil && parent.Attrs() != nil {
		parentIndex = parent.Attrs().Index
	}

	var ifindices []int
	for _, candidate := range links {
		attrs := candidate.Attrs()
		if attrs == nil || attrs.Index <= 0 || attrs.Name == "" {
			continue
		}
		if attrs.Name == "lo" {
			continue
		}
		if parentIndex != 0 && attrs.Index == parentIndex {
			continue
		}
		if parentIndex != 0 && attrs.MasterIndex == parentIndex {
			continue
		}
		if candidate.Type() == "netkit" {
			continue
		}
		ifindices = append(ifindices, attrs.Index)
	}
	return ifindices
}

func bridgeSlaveLinkIndices(parent netlink.Link, links []netlink.Link) []int {
	parentAttrs := parent.Attrs()
	if parentAttrs == nil {
		return nil
	}

	var ifindices []int
	for _, candidate := range links {
		attrs := candidate.Attrs()
		if attrs == nil || attrs.Index <= 0 || attrs.MasterIndex != parentAttrs.Index {
			continue
		}
		ifindices = append(ifindices, attrs.Index)
	}
	return ifindices
}

var _ publishedPortDatapath = (*ebpfPublishedPortDatapath)(nil)
