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
