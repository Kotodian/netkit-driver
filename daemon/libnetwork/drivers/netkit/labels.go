//go:build linux

package netkit

const (
	containerVethPrefix = "eth"
	hostIfPrefix        = "nk"
	hostIfLen           = len(hostIfPrefix) + 7
	probeIfPrefix       = "nkprb"
	probeIfLen          = len(probeIfPrefix) + 7

	NetworkType = "netkit"
	parentOpt   = "parent"
	bigTCPOpt   = "com.docker.network.netkit.big_tcp"
)
