//go:build linux

package netkit

import (
	"bytes"
	_ "embed"

	"github.com/cilium/ebpf"
)

//go:embed bpf/netkit_portmap_bpfel.o
var netkitPortmapBpfEL []byte

func loadNetkitPortmap() (*ebpf.CollectionSpec, error) {
	return ebpf.LoadCollectionSpecFromReader(bytes.NewReader(netkitPortmapBpfEL))
}
