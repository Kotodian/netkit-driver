//go:build linux

package netkit

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/moby/moby/v2/errdefs"
)

type endpointNetkitDatapath interface {
	AttachEndpoint(hostIf string) error
	DetachEndpoint(hostIf string) error
	UpsertLocalEndpoint(ep localEndpointConfig) error
	RemoveLocalEndpoint(ep localEndpointConfig) error
	Close() error
}

var newEndpointNetkitDatapath = func(ctx context.Context) (endpointNetkitDatapath, error) {
	return newEBPFEndpointNetkitDatapath(ctx)
}

var attachNetkit = link.AttachNetkit
var probeNetkitAttach = probeNetkitAttachPrograms

type ebpfEndpointNetkitDatapath struct {
	mu sync.Mutex

	handles     netkitEndpointHandles
	attachments map[string][]link.Link
}

type netkitEndpointHandles struct {
	EndpointPrimary  *ebpf.Program `ebpf:"endpoint_primary"`
	EndpointPeer     *ebpf.Program `ebpf:"endpoint_peer"`
	LocalSources     *ebpf.Map     `ebpf:"local_sources"`
	LocalEndpointsV4 *ebpf.Map     `ebpf:"local_endpoints_v4"`
	LocalEndpointsV6 *ebpf.Map     `ebpf:"local_endpoints_v6"`
}

func newEBPFEndpointNetkitDatapath(_ context.Context) (endpointNetkitDatapath, error) {
	spec, err := loadNetkitPortmap()
	if err != nil {
		return nil, fmt.Errorf("load netkit endpoint bpf spec: %w", err)
	}

	var handles netkitEndpointHandles
	if err := spec.LoadAndAssign(&handles, nil); err != nil {
		return nil, classifyEndpointNetkitDatapathError("load netkit endpoint bpf objects", err)
	}

	return &ebpfEndpointNetkitDatapath{
		handles:     handles,
		attachments: map[string][]link.Link{},
	}, nil
}

func (d *ebpfEndpointNetkitDatapath) AttachEndpoint(hostIf string) error {
	if hostIf == "" {
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if _, ok := d.attachments[hostIf]; ok {
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

	d.attachments[hostIf] = []link.Link{primary, peer}
	return nil
}

func (d *ebpfEndpointNetkitDatapath) DetachEndpoint(hostIf string) error {
	if hostIf == "" {
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	links := d.attachments[hostIf]
	delete(d.attachments, hostIf)
	return closeLinks(links)
}

func (d *ebpfEndpointNetkitDatapath) UpsertLocalEndpoint(ep localEndpointConfig) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	return upsertLocalEndpoint(d.handles.LocalSources, d.handles.LocalEndpointsV4, d.handles.LocalEndpointsV6, ep)
}

func (d *ebpfEndpointNetkitDatapath) RemoveLocalEndpoint(ep localEndpointConfig) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	return removeLocalEndpoint(d.handles.LocalSources, d.handles.LocalEndpointsV4, d.handles.LocalEndpointsV6, ep)
}

func (d *ebpfEndpointNetkitDatapath) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	var errs []error
	for hostIf, links := range d.attachments {
		errs = append(errs, closeLinks(links))
		delete(d.attachments, hostIf)
	}
	errs = append(errs, d.handles.Close())
	return errors.Join(errs...)
}

func (h *netkitEndpointHandles) Close() error {
	return errors.Join(
		closeMap(h.LocalEndpointsV6),
		closeMap(h.LocalEndpointsV4),
		closeMap(h.LocalSources),
		closeProgram(h.EndpointPrimary),
		closeProgram(h.EndpointPeer),
	)
}

func classifyEndpointNetkitDatapathError(op string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ebpf.ErrNotSupported) || errors.Is(err, link.ErrNotSupported) || looksLikeUnsupportedDatapathError(err) {
		return errdefs.NotImplemented(fmt.Errorf("netkit endpoint datapath unsupported on this kernel during %s: %w", op, err))
	}
	return fmt.Errorf("%s: %w", op, err)
}

func probeNetkitAttachPrograms(ifindex int) error {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:    ebpf.SchedCLS,
		License: "MIT",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
	})
	if err != nil {
		return err
	}
	defer prog.Close()

	primary, err := attachNetkit(link.NetkitOptions{
		Interface: ifindex,
		Program:   prog,
		Attach:    ebpf.AttachNetkitPrimary,
	})
	if err != nil {
		return err
	}
	defer primary.Close()

	peer, err := attachNetkit(link.NetkitOptions{
		Interface: ifindex,
		Program:   prog,
		Attach:    ebpf.AttachNetkitPeer,
	})
	if err != nil {
		return err
	}
	defer peer.Close()

	return nil
}

func (d *driver) attachEndpointDatapath(ctx context.Context, ep *endpoint) error {
	if ep == nil || ep.hostIf == "" {
		return nil
	}

	d.configNetwork.Lock()
	if d.datapath != nil && d.endpointUsesSharedDatapathLocked(ep) {
		dp := d.datapath
		if d.sharedDatapathLinks == nil {
			d.sharedDatapathLinks = map[string]struct{}{}
		}
		err := dp.AttachEndpoint(ep.hostIf)
		if err == nil {
			d.sharedDatapathLinks[endpointDatapathKey(ep)] = struct{}{}
		}
		d.configNetwork.Unlock()
		return err
	}
	d.configNetwork.Unlock()

	d.mu.Lock()
	dp := d.endpointDatapath
	if dp == nil {
		ctor := d.newEndpointDatapath
		if ctor == nil {
			ctor = newEndpointNetkitDatapath
		}
		d.mu.Unlock()

		newDP, err := ctor(ctx)
		if err != nil {
			return err
		}
		if err := d.syncLocalEndpointsToEndpointDatapath(newDP); err != nil {
			_ = newDP.Close()
			return err
		}

		d.mu.Lock()
		if d.endpointDatapath == nil {
			d.endpointDatapath = newDP
			dp = newDP
			newDP = nil
		} else {
			dp = d.endpointDatapath
		}
		d.mu.Unlock()
		if newDP != nil {
			_ = newDP.Close()
		}
	} else {
		d.mu.Unlock()
	}

	return dp.AttachEndpoint(ep.hostIf)
}

func (d *driver) detachEndpointDatapath(ep *endpoint) error {
	if ep == nil || ep.hostIf == "" {
		return nil
	}

	d.configNetwork.Lock()
	if _, ok := d.sharedDatapathLinks[endpointDatapathKey(ep)]; ok {
		dp := d.datapath
		delete(d.sharedDatapathLinks, endpointDatapathKey(ep))
		d.configNetwork.Unlock()
		if dp == nil {
			return nil
		}
		return dp.DetachEndpoint(ep.hostIf)
	}
	d.configNetwork.Unlock()

	d.mu.Lock()
	dp := d.endpointDatapath
	d.mu.Unlock()
	if dp == nil {
		return nil
	}
	return dp.DetachEndpoint(ep.hostIf)
}

func (d *driver) endpointUsesSharedDatapathLocked(ep *endpoint) bool {
	if ep == nil {
		return false
	}
	if ep.publishedParent != "" {
		return true
	}
	_, ok := d.datapathEndpoints[endpointDatapathKey(ep)]
	return ok
}
