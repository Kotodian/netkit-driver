//go:build linux

package netkit

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/containerd/log"
	"github.com/moby/moby/v2/daemon/libnetwork/nlwrap"
	"github.com/moby/moby/v2/daemon/libnetwork/ns"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

var createNetkitFn = createNetkit

const netkitBigTCPMaxSize = 196608

type bigTCPConfigurer interface {
	LinkSetGSOMaxSize(netlink.Link, int) error
	LinkSetGROMaxSize(netlink.Link, int) error
	LinkSetGSOIPv4MaxSize(netlink.Link, int) error
	LinkSetGROIPv4MaxSize(netlink.Link, int) error
}

func createNetkit(hostIfName, containerIfName, parent, sboxKey string, mac net.HardwareAddr, enableBigTCP bool) error {
	_ = parent
	_ = mac

	netnsh, err := netns.GetFromPath(sboxKey)
	if err != nil {
		return fmt.Errorf("failed to open sandbox netns %q: %w", sboxKey, err)
	}
	defer netnsh.Close()

	// Scrub and PeerScrub must be set explicitly: the netlink library
	// always serialises these attributes, and the Go zero value maps to
	// NETKIT_SCRUB_NONE, which would silently override the kernel's
	// NETKIT_SCRUB_DEFAULT and leak skb->mark / skb->priority across
	// netns. These attributes are create-time only and cannot be changed
	// after the device exists.
	nk := &netlink.Netkit{
		LinkAttrs:  netlink.LinkAttrs{Name: hostIfName, TxQLen: 0},
		Mode:       netlink.NETKIT_MODE_L3,
		Policy:     netlink.NETKIT_POLICY_BLACKHOLE,
		PeerPolicy: netlink.NETKIT_POLICY_BLACKHOLE,
		Scrub:      netlink.NETKIT_SCRUB_DEFAULT,
		PeerScrub:  netlink.NETKIT_SCRUB_DEFAULT,
	}

	peerAttrs := &netlink.LinkAttrs{
		Name:      containerIfName,
		Namespace: netlink.NsFd(netnsh),
	}
	nk.SetPeerAttrs(peerAttrs)

	if err := ns.NlHandle().LinkAdd(nk); err != nil {
		return fmt.Errorf("failed to create netkit pair %s/%s: %w", hostIfName, containerIfName, err)
	}

	hostLink, err := ns.NlHandle().LinkByName(hostIfName)
	if err != nil {
		return fmt.Errorf("failed to find netkit primary %s: %w", hostIfName, err)
	}
	if err := ns.NlHandle().LinkSetUp(hostLink); err != nil {
		_ = ns.NlHandle().LinkDel(hostLink)
		return fmt.Errorf("failed to bring up netkit primary %s: %w", hostIfName, err)
	}
	if enableBigTCP {
		if err := configureNetkitBigTCP(hostLink, netnsh, containerIfName); err != nil {
			log.G(context.TODO()).Debugf("failed to enable BIG TCP max sizes on netkit pair %s/%s: %v", hostIfName, containerIfName, err)
		}
	}
	return nil
}

func configureNetkitBigTCP(hostLink netlink.Link, peerNetns netns.NsHandle, peerName string) error {
	errs := []error{
		setLinkBigTCPMaxSizes(ns.NlHandle(), hostLink),
	}

	peerHandle, err := nlwrap.NewHandleAt(peerNetns)
	if err != nil {
		errs = append(errs, fmt.Errorf("open peer netns handle: %w", err))
		return errors.Join(errs...)
	}
	defer peerHandle.Close()

	peerLink, err := peerHandle.LinkByName(peerName)
	if err != nil {
		errs = append(errs, fmt.Errorf("find peer link %s: %w", peerName, err))
		return errors.Join(errs...)
	}
	errs = append(errs, setLinkBigTCPMaxSizes(peerHandle, peerLink))
	return errors.Join(errs...)
}

func setLinkBigTCPMaxSizes(h bigTCPConfigurer, link netlink.Link) error {
	return errors.Join(
		h.LinkSetGROMaxSize(link, netkitBigTCPMaxSize),
		h.LinkSetGSOMaxSize(link, netkitBigTCPMaxSize),
		h.LinkSetGROIPv4MaxSize(link, netkitBigTCPMaxSize),
		h.LinkSetGSOIPv4MaxSize(link, netkitBigTCPMaxSize),
	)
}
