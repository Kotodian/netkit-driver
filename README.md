# Docker Netkit Driver

This repository contains the experimental Docker/Moby `netkit` network driver
subtree.

The driver is kept in its original Moby path:

```text
daemon/libnetwork/drivers/netkit
```

It is not a standalone Docker network plugin. The code depends on Moby and
libnetwork internal packages, so it is intended to be copied or patched back
into a matching Moby checkout.

## What Is Included

- Linux netkit L3 endpoint driver code.
- eBPF datapath for published ports, host access, endpoint-to-endpoint traffic,
  egress masquerade, and local socket rewriting.
- Embedded BPF object generated from `bpf/netkit_portmap.c`.
- Driver unit tests that live with the Moby libnetwork driver package.

## Performance

Container-to-container throughput, measured inside a virtio VM with `iperf3`.
Each number is the average of three runs.

| Datapath | Streams | Throughput | VM CPU | Softirq CPU | Retransmits |
|:--|--:|--:|--:|--:|--:|
| veth | 1 | 65.98 Gbit/s | 87.8% | 0.02% | 0 |
| netkit | 1 | 75.21 Gbit/s | 82.3% | 0.02% | 0 |
| veth | 4 | 117.10 Gbit/s | 98.4% | 0.00% | 2902 |
| netkit | 4 | 146.56 Gbit/s | 98.3% | 0.02% | 0 |

| Comparison | Gain |
|:--|--:|
| netkit vs veth, 1 stream | +14.0% |
| netkit vs veth, 4 streams | +25.2% |

## Kernel Requirements

The driver requires Linux netkit support and BPF netkit attachment support. In
practice, test against Linux 6.8 or newer; newer kernels are preferred for TCX,
cgroup socket hooks, and BIG TCP validation.

## Syncing Back Into Moby

From a Moby checkout:

```sh
rsync -a --delete daemon/libnetwork/drivers/netkit/ \
  /path/to/moby/daemon/libnetwork/drivers/netkit/
```

Then run the Moby-side checks:

```sh
go test ./daemon/libnetwork/drivers/netkit -count=1
go test ./daemon/libnetwork/drivers/... -run TestDoesNotExist -count=0
```

If `bpf/netkit_portmap.c` changes, regenerate the embedded object from the
Moby driver directory:

```sh
clang -target bpf -O2 -g -D__TARGET_ARCH_x86 -I./bpf \
  -c ./bpf/netkit_portmap.c -o ./bpf/netkit_portmap_bpfel.o
```

## License

This subtree follows the Moby project license. See `LICENSE` and `NOTICE`.
