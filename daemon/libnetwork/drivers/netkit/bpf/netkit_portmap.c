#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#ifdef NETKIT_PORTMAP_DEBUG
#define netkit_dbg(fmt, ...) bpf_printk("netkit-portmap: " fmt, ##__VA_ARGS__)
#else
#define netkit_dbg(fmt, ...) ((void)0)
#endif

#define AF_INET 2
#define AF_INET6 10
#define ETH_P_IP 0x0800
#define ETH_P_8021Q 0x8100
#define ETH_P_IPV6 0x86DD
#define ETH_P_8021AD 0x88A8
#define IP_MF 0x2000
#define IP_OFFSET 0x1fff
#define NEXTHDR_HOP 0
#define IPV6_TLV_JUMBO 194
#define IPPROTO_ICMPV6 58
#define ICMP_ECHOREPLY 0
#define ICMP_ECHO 8
#define ICMPV6_ECHO_REQUEST 128
#define ICMPV6_ECHO_REPLY 129
#define PUBLISHED_IFACE_F_REDIRECT_REPLY 0x1
#define EGRESS_ENDPOINT_F_MASQUERADE 0x1

volatile const __u64 host_netns_cookie = 0;

struct published_port_v4_key {
	__u32 host_ip;
	__u16 host_port;
	__u8 proto;
	__u8 flags;
};

struct published_port_v4_value {
	__u32 endpoint_ip;
	__u16 endpoint_port;
	__u16 flags;
	__u32 ifindex;
};

struct published_port_v6_key {
	__u8 host_ip[16];
	__u16 host_port;
	__u8 proto;
	__u8 flags;
};

struct published_port_v6_value {
	__u8 endpoint_ip[16];
	__u16 endpoint_port;
	__u16 flags;
	__u32 ifindex;
};

struct published_flow_v4_key {
	__u32 src_ip;
	__u32 dst_ip;
	__u16 src_port;
	__u16 dst_port;
	__u8 proto;
	__u8 pad1;
	__u16 pad2;
};

struct published_flow_v4_value {
	__u32 frontend_ip;
	__u16 frontend_port;
	__u16 flags;
	__u32 ifindex;
};

struct published_flow_v6_key {
	__u8 src_ip[16];
	__u8 dst_ip[16];
	__u16 src_port;
	__u16 dst_port;
	__u8 proto;
	__u8 pad1;
	__u16 pad2;
};

struct published_flow_v6_value {
	__u8 frontend_ip[16];
	__u16 frontend_port;
	__u16 flags;
	__u32 ifindex;
};

struct published_sock_v4_value {
	__u32 frontend_ip;
	__u32 backend_ip;
	__u16 frontend_port;
	__u16 backend_port;
	__u8 proto;
	__u8 flags;
	__u16 pad;
};

struct published_sock_v6_value {
	__u8 frontend_ip[16];
	__u8 backend_ip[16];
	__u16 frontend_port;
	__u16 backend_port;
	__u8 proto;
	__u8 flags;
	__u16 pad;
};

struct published_iface_value {
	__u8 flags;
	__u8 pad1;
	__u16 pad2;
};

struct egress_endpoint_v4_key {
	__u32 endpoint_ip;
};

struct egress_endpoint_v4_value {
	__u32 host_ip;
	__u8 flags;
	__u8 pad1;
	__u16 pad2;
	__u32 ifindex;
};

struct egress_endpoint_v6_key {
	__u8 endpoint_ip[16];
};

struct egress_endpoint_v6_value {
	__u8 host_ip[16];
	__u8 flags;
	__u8 pad1;
	__u16 pad2;
	__u32 ifindex;
};

struct egress_flow_v4_key {
	__u32 src_ip;
	__u32 dst_ip;
	__u16 src_port;
	__u16 dst_port;
	__u8 proto;
	__u8 pad1;
	__u16 pad2;
};

struct egress_flow_v4_value {
	__u32 endpoint_ip;
	__u32 ifindex;
};

struct egress_flow_v6_key {
	__u8 src_ip[16];
	__u8 dst_ip[16];
	__u16 src_port;
	__u16 dst_port;
	__u8 proto;
	__u8 pad1;
	__u16 pad2;
};

struct egress_flow_v6_value {
	__u8 endpoint_ip[16];
	__u32 ifindex;
};

struct egress_iface_value {
	__u32 ipv4;
	__u8 ipv6[16];
};

struct local_source_value {
	__u8 network_id[16];
};

struct local_endpoint_v4_key {
	__u8 network_id[16];
	__u32 endpoint_ip;
};

struct local_endpoint_v6_key {
	__u8 network_id[16];
	__u8 endpoint_ip[16];
};

struct local_endpoint_value {
	__u32 ifindex;
};

struct packet_info {
	__u32 l3_off;
	__u32 l4_off;
	__u32 l4_csum_off;
	__u16 l3_len;
	__u8 family;
	__u8 proto;
	__u8 tos;
	__u8 pad1;
	__be32 saddr4;
	__be32 daddr4;
	struct in6_addr saddr6;
	struct in6_addr daddr6;
	__be16 sport;
	__be16 dport;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct published_port_v4_key);
	__type(value, struct published_port_v4_value);
} published_ports_v4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct published_port_v6_key);
	__type(value, struct published_port_v6_value);
} published_ports_v6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 32768);
	__type(key, struct published_flow_v4_key);
	__type(value, struct published_flow_v4_value);
} published_flows_v4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 32768);
	__type(key, struct published_flow_v6_key);
	__type(value, struct published_flow_v6_value);
} published_flows_v6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct published_sock_v4_value);
} published_sock_v4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct published_sock_v6_value);
} published_sock_v6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, struct published_iface_value);
} published_ifaces SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, struct egress_endpoint_v4_key);
	__type(value, struct egress_endpoint_v4_value);
} egress_endpoints_v4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, struct egress_endpoint_v6_key);
	__type(value, struct egress_endpoint_v6_value);
} egress_endpoints_v6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 32768);
	__type(key, struct egress_flow_v4_key);
	__type(value, struct egress_flow_v4_value);
} egress_flows_v4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 32768);
	__type(key, struct egress_flow_v6_key);
	__type(value, struct egress_flow_v6_value);
} egress_flows_v6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, struct egress_iface_value);
} egress_ifaces SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, struct local_source_value);
} local_sources SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, struct local_endpoint_v4_key);
	__type(value, struct local_endpoint_value);
} local_endpoints_v4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, struct local_endpoint_v6_key);
	__type(value, struct local_endpoint_value);
} local_endpoints_v6 SEC(".maps");

static __always_inline int is_loopback_v4(__be32 addr)
{
	return (bpf_ntohl(addr) & 0xff000000U) == 0x7f000000U;
}

static __always_inline int is_loopback_v6(const struct in6_addr *addr)
{
	const __u8 *bytes = (const __u8 *)addr;

	return bytes[0] == 0 && bytes[1] == 0 && bytes[2] == 0 && bytes[3] == 0 &&
	       bytes[4] == 0 && bytes[5] == 0 && bytes[6] == 0 && bytes[7] == 0 &&
	       bytes[8] == 0 && bytes[9] == 0 && bytes[10] == 0 && bytes[11] == 0 &&
	       bytes[12] == 0 && bytes[13] == 0 && bytes[14] == 0 && bytes[15] == 1;
}

static __always_inline __u32 redirect_reply_ifindex(__u32 ifindex)
{
	const struct published_iface_value *value;

	value = bpf_map_lookup_elem(&published_ifaces, &ifindex);
	if (!value || (value->flags & PUBLISHED_IFACE_F_REDIRECT_REPLY) == 0)
		return 0;
	return ifindex;
}

static __always_inline int iface_is_host_facing(__u32 ifindex)
{
	const struct published_iface_value *value;

	value = bpf_map_lookup_elem(&published_ifaces, &ifindex);
	if (!value)
		return 0;
	return (value->flags & PUBLISHED_IFACE_F_REDIRECT_REPLY) != 0;
}

static __always_inline int parse_l3(void *data, void *data_end, __be16 skb_proto,
				    __u32 *l3_off, __be16 *l3_proto)
{
	__u8 version;
	struct ethhdr *eth;
	__be16 proto;
	__u32 off = 0;

	if (data + 1 > data_end)
		return -1;

	version = *(__u8 *)data >> 4;
	if (skb_proto == bpf_htons(ETH_P_IP) && version == 4) {
		*l3_off = 0;
		*l3_proto = skb_proto;
		return 0;
	}
	if (skb_proto == bpf_htons(ETH_P_IPV6) && version == 6) {
		*l3_off = 0;
		*l3_proto = skb_proto;
		return 0;
	}

	eth = data;
	if ((void *)(eth + 1) > data_end)
		return -1;

	proto = eth->h_proto;
	off = sizeof(*eth);
	if (proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD)) {
		struct vlan_hdr *vh = data + off;

		if ((void *)(vh + 1) > data_end)
			return -1;
		proto = vh->h_vlan_encapsulated_proto;
		off += sizeof(*vh);
	}

	if (proto != bpf_htons(ETH_P_IP) && proto != bpf_htons(ETH_P_IPV6))
		return -1;

	*l3_off = off;
	*l3_proto = proto;
	return 0;
}

static __always_inline int parse_ipv6_l4(struct __sk_buff *skb, struct packet_info *pkt,
					 void *data, void *data_end, const struct ipv6hdr *ip6h)
{
	(void)skb;

	if (ip6h->payload_len == 0 && ip6h->nexthdr == NEXTHDR_HOP) {
		struct hop_jumbo_hdr *hop = data + pkt->l4_off;

		if ((void *)(hop + 1) > data_end)
			return -1;
		if (hop->tlv_type != IPV6_TLV_JUMBO || hop->tlv_len != sizeof(hop->jumbo_payload_len))
			return -1;
		if (hop->hdrlen != 0 || hop->nexthdr != IPPROTO_TCP)
			return -1;

		pkt->proto = hop->nexthdr;
		pkt->l3_len = bpf_ntohl(hop->jumbo_payload_len) + sizeof(*ip6h);
		pkt->l4_off += sizeof(*hop);
	}

	if (pkt->proto == IPPROTO_TCP) {
		struct tcphdr *tcph = data + pkt->l4_off;

		if ((void *)(tcph + 1) > data_end)
			return -1;
		pkt->sport = tcph->source;
		pkt->dport = tcph->dest;
		pkt->l4_csum_off = pkt->l4_off + offsetof(struct tcphdr, check);
		return 0;
	}

	if (pkt->proto == IPPROTO_UDP) {
		struct udphdr *udph = data + pkt->l4_off;

		if ((void *)(udph + 1) > data_end)
			return -1;
		pkt->sport = udph->source;
		pkt->dport = udph->dest;
		pkt->l4_csum_off = pkt->l4_off + offsetof(struct udphdr, check);
		return 0;
	}

	if (pkt->proto == IPPROTO_ICMPV6) {
		struct icmp6hdr *icmp6h = data + pkt->l4_off;

		if ((void *)(icmp6h + 1) > data_end)
			return -1;
		pkt->l4_csum_off = pkt->l4_off + offsetof(struct icmp6hdr, icmp6_cksum);
		if (icmp6h->icmp6_type == ICMPV6_ECHO_REQUEST ||
		    icmp6h->icmp6_type == ICMPV6_ECHO_REPLY) {
			pkt->sport = icmp6h->icmp6_dataun.u_echo.identifier;
			pkt->dport = icmp6h->icmp6_dataun.u_echo.identifier;
		}
	}

	return 0;
}

static __always_inline int parse_packet(struct __sk_buff *skb, struct packet_info *pkt)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	__be16 l3_proto;

	if (parse_l3(data, data_end, skb->protocol, &pkt->l3_off, &l3_proto) < 0)
		return -1;

	if (l3_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph = data + pkt->l3_off;
		__u32 ihl;

		if ((void *)(iph + 1) > data_end)
			return -1;
		if (iph->version != 4)
			return -1;
		if (iph->frag_off & bpf_htons(IP_MF | IP_OFFSET))
			return -1;

		ihl = (__u32)iph->ihl * 4;
		if (ihl < sizeof(*iph))
			return -1;
		if (data + pkt->l3_off + ihl > data_end)
			return -1;

		pkt->family = AF_INET;
		pkt->proto = iph->protocol;
		pkt->tos = iph->tos;
		pkt->l3_len = bpf_ntohs(iph->tot_len);
		pkt->saddr4 = iph->saddr;
		pkt->daddr4 = iph->daddr;
		pkt->l4_off = pkt->l3_off + ihl;

		if (pkt->proto == IPPROTO_TCP) {
			struct tcphdr *tcph = data + pkt->l4_off;

			if ((void *)(tcph + 1) > data_end)
				return -1;
			pkt->sport = tcph->source;
			pkt->dport = tcph->dest;
			pkt->l4_csum_off = pkt->l4_off + offsetof(struct tcphdr, check);
			return 0;
		}

		if (pkt->proto == IPPROTO_UDP) {
			struct udphdr *udph = data + pkt->l4_off;

			if ((void *)(udph + 1) > data_end)
				return -1;
			pkt->sport = udph->source;
			pkt->dport = udph->dest;
			pkt->l4_csum_off = pkt->l4_off + offsetof(struct udphdr, check);
			return 0;
		}

		if (pkt->proto == IPPROTO_ICMP) {
			struct icmphdr *icmph = data + pkt->l4_off;

			if ((void *)(icmph + 1) > data_end)
				return -1;
			pkt->l4_csum_off = pkt->l4_off + offsetof(struct icmphdr, checksum);
			if (icmph->type == ICMP_ECHO || icmph->type == ICMP_ECHOREPLY) {
				pkt->sport = icmph->un.echo.id;
				pkt->dport = icmph->un.echo.id;
			}
			return 0;
		}

		return -1;
	}

	if (l3_proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6h = data + pkt->l3_off;

		if ((void *)(ip6h + 1) > data_end)
			return -1;
		if (ip6h->version != 6)
			return -1;

		pkt->family = AF_INET6;
		pkt->proto = ip6h->nexthdr;
		pkt->tos = 0;
		pkt->l3_len = bpf_ntohs(ip6h->payload_len) + sizeof(*ip6h);
		pkt->saddr6 = ip6h->saddr;
		pkt->daddr6 = ip6h->daddr;
		pkt->l4_off = pkt->l3_off + sizeof(*ip6h);

		return parse_ipv6_l4(skb, pkt, data, data_end, ip6h);
	}

	return -1;
}

static __always_inline int lookup_published_port_v4(const struct packet_info *pkt,
						    const struct published_port_v4_value **value)
{
	__u8 loopback = is_loopback_v4(pkt->daddr4) ? 1 : 0;
	struct published_port_v4_key key = {
		.host_ip = bpf_ntohl(pkt->daddr4),
		.host_port = bpf_ntohs(pkt->dport),
		.proto = pkt->proto,
		.flags = loopback,
	};

	*value = bpf_map_lookup_elem(&published_ports_v4, &key);
	if (*value)
		return 0;

	key.host_ip = 0;
	*value = bpf_map_lookup_elem(&published_ports_v4, &key);
	if (*value)
		return 0;
	if (loopback == 0)
		return -1;

	key.flags = 0;
	*value = bpf_map_lookup_elem(&published_ports_v4, &key);
	return *value ? 0 : -1;
}

static __always_inline int lookup_published_port_v6(const struct packet_info *pkt,
						    const struct published_port_v6_value **value)
{
	__u8 loopback = is_loopback_v6(&pkt->daddr6) ? 1 : 0;
	struct published_port_v6_key key = {
		.host_port = bpf_ntohs(pkt->dport),
		.proto = pkt->proto,
		.flags = loopback,
	};

	__builtin_memcpy(key.host_ip, pkt->daddr6.in6_u.u6_addr8, sizeof(key.host_ip));
	*value = bpf_map_lookup_elem(&published_ports_v6, &key);
	if (*value)
		return 0;

	__builtin_memset(key.host_ip, 0, sizeof(key.host_ip));
	*value = bpf_map_lookup_elem(&published_ports_v6, &key);
	if (*value)
		return 0;
	if (loopback == 0)
		return -1;

	key.flags = 0;
	*value = bpf_map_lookup_elem(&published_ports_v6, &key);
	return *value ? 0 : -1;
}

static __always_inline int lookup_sock_published_port_v4(struct bpf_sock_addr *ctx,
							  const struct published_port_v4_value **value)
{
	__u8 loopback = is_loopback_v4((__be32)ctx->user_ip4) ? 1 : 0;
	struct published_port_v4_key key = {
		.host_ip = bpf_ntohl(ctx->user_ip4),
		.host_port = bpf_ntohs((__be16)ctx->user_port),
		.proto = ctx->protocol,
		.flags = loopback,
	};

	*value = bpf_map_lookup_elem(&published_ports_v4, &key);
	if (*value)
		return 0;

	key.host_ip = 0;
	*value = bpf_map_lookup_elem(&published_ports_v4, &key);
	if (*value)
		return 0;
	if (loopback == 0)
		return -1;

	key.flags = 0;
	*value = bpf_map_lookup_elem(&published_ports_v4, &key);
	return *value ? 0 : -1;
}

static __always_inline int lookup_sock_published_port_v6(struct bpf_sock_addr *ctx,
							  const struct published_port_v6_value **value)
{
	struct in6_addr daddr = {};
	__u8 loopback;
	struct published_port_v6_key key = {
		.host_port = bpf_ntohs((__be16)ctx->user_port),
		.proto = ctx->protocol,
	};

	((__u32 *)daddr.in6_u.u6_addr8)[0] = ctx->user_ip6[0];
	((__u32 *)daddr.in6_u.u6_addr8)[1] = ctx->user_ip6[1];
	((__u32 *)daddr.in6_u.u6_addr8)[2] = ctx->user_ip6[2];
	((__u32 *)daddr.in6_u.u6_addr8)[3] = ctx->user_ip6[3];
	loopback = is_loopback_v6(&daddr) ? 1 : 0;
	key.flags = loopback;
	((__u32 *)key.host_ip)[0] = ctx->user_ip6[0];
	((__u32 *)key.host_ip)[1] = ctx->user_ip6[1];
	((__u32 *)key.host_ip)[2] = ctx->user_ip6[2];
	((__u32 *)key.host_ip)[3] = ctx->user_ip6[3];

	*value = bpf_map_lookup_elem(&published_ports_v6, &key);
	if (*value)
		return 0;

	__builtin_memset(key.host_ip, 0, sizeof(key.host_ip));
	*value = bpf_map_lookup_elem(&published_ports_v6, &key);
	if (*value)
		return 0;
	if (loopback == 0)
		return -1;

	key.flags = 0;
	*value = bpf_map_lookup_elem(&published_ports_v6, &key);
	return *value ? 0 : -1;
}

static __always_inline int lookup_egress_endpoint_v4(const struct packet_info *pkt,
						     const struct egress_endpoint_v4_value **value)
{
	struct egress_endpoint_v4_key key = {
		.endpoint_ip = bpf_ntohl(pkt->saddr4),
	};

	*value = bpf_map_lookup_elem(&egress_endpoints_v4, &key);
	return *value ? 0 : -1;
}

static __always_inline int lookup_egress_endpoint_v6(const struct packet_info *pkt,
						     const struct egress_endpoint_v6_value **value)
{
	struct egress_endpoint_v6_key key = {};

	__builtin_memcpy(key.endpoint_ip, pkt->saddr6.in6_u.u6_addr8, sizeof(key.endpoint_ip));
	*value = bpf_map_lookup_elem(&egress_endpoints_v6, &key);
	return *value ? 0 : -1;
}

static __always_inline int redirect_local_endpoint_v4(__u32 ifindex, const struct packet_info *pkt,
						      const struct local_source_value *source)
{
	struct local_endpoint_v4_key key = {};
	const struct local_endpoint_value *value;

	__builtin_memcpy(key.network_id, source->network_id, sizeof(key.network_id));
	key.endpoint_ip = bpf_ntohl(pkt->daddr4);
	value = bpf_map_lookup_elem(&local_endpoints_v4, &key);
	if (!value || value->ifindex == 0 || value->ifindex == ifindex)
		return TCX_NEXT;
	/*
	 * netkit/peer already runs while the skb is crossing from the source
	 * peer into the host-side primary. Redirect to the destination primary;
	 * netkit xmit then delivers it to that endpoint's peer.
	 */
	return bpf_redirect(value->ifindex, 0);
}

static __always_inline int redirect_local_endpoint_v6(__u32 ifindex, const struct packet_info *pkt,
						      const struct local_source_value *source)
{
	struct local_endpoint_v6_key key = {};
	const struct local_endpoint_value *value;

	__builtin_memcpy(key.network_id, source->network_id, sizeof(key.network_id));
	__builtin_memcpy(key.endpoint_ip, pkt->daddr6.in6_u.u6_addr8, sizeof(key.endpoint_ip));
	value = bpf_map_lookup_elem(&local_endpoints_v6, &key);
	if (!value || value->ifindex == 0 || value->ifindex == ifindex)
		return TCX_NEXT;
	/*
	 * See the IPv4 path: redirect to the target primary, not to the target
	 * peer, from a netkit peer hook.
	 */
	return bpf_redirect(value->ifindex, 0);
}

static __always_inline int redirect_local_endpoint(struct __sk_buff *skb, const struct packet_info *pkt)
{
	__u32 ifindex = skb->ifindex;
	const struct local_source_value *source;

	source = bpf_map_lookup_elem(&local_sources, &ifindex);
	if (!source)
		return TCX_NEXT;

	if (pkt->family == AF_INET)
		return redirect_local_endpoint_v4(ifindex, pkt, source);
	if (pkt->family == AF_INET6)
		return redirect_local_endpoint_v6(ifindex, pkt, source);
	return TCX_NEXT;
}

static __always_inline int lookup_egress_flow_v4(const struct packet_info *pkt,
						 const struct egress_flow_v4_value **value)
{
	struct egress_flow_v4_key key = {
		.src_ip = bpf_ntohl(pkt->saddr4),
		.dst_ip = bpf_ntohl(pkt->daddr4),
		.src_port = bpf_ntohs(pkt->sport),
		.dst_port = bpf_ntohs(pkt->dport),
		.proto = pkt->proto,
	};

	*value = bpf_map_lookup_elem(&egress_flows_v4, &key);
	return *value ? 0 : -1;
}

static __always_inline int lookup_egress_flow_v6(const struct packet_info *pkt,
						 const struct egress_flow_v6_value **value)
{
	struct egress_flow_v6_key key = {
		.src_port = bpf_ntohs(pkt->sport),
		.dst_port = bpf_ntohs(pkt->dport),
		.proto = pkt->proto,
	};

	__builtin_memcpy(key.src_ip, pkt->saddr6.in6_u.u6_addr8, sizeof(key.src_ip));
	__builtin_memcpy(key.dst_ip, pkt->daddr6.in6_u.u6_addr8, sizeof(key.dst_ip));
	*value = bpf_map_lookup_elem(&egress_flows_v6, &key);
	return *value ? 0 : -1;
}

static __always_inline int resolve_egress_ipv4(__u32 ifindex, const struct egress_endpoint_v4_value *value,
					       __u32 *host_ip)
{
	if ((value->flags & EGRESS_ENDPOINT_F_MASQUERADE) == 0) {
		*host_ip = value->host_ip;
		return value->host_ip != 0 ? 0 : -1;
	}

	const struct egress_iface_value *iface = bpf_map_lookup_elem(&egress_ifaces, &ifindex);
	if (!iface || iface->ipv4 == 0)
		return -1;
	*host_ip = iface->ipv4;
	return 0;
}

static __always_inline int resolve_egress_ipv6(__u32 ifindex, const struct egress_endpoint_v6_value *value,
					       __u8 host_ip[16])
{
	if ((value->flags & EGRESS_ENDPOINT_F_MASQUERADE) == 0) {
		if (((const __u32 *)value->host_ip)[0] == 0 && ((const __u32 *)value->host_ip)[1] == 0 &&
		    ((const __u32 *)value->host_ip)[2] == 0 && ((const __u32 *)value->host_ip)[3] == 0)
			return -1;
		__builtin_memcpy(host_ip, value->host_ip, 16);
		return 0;
	}

	const struct egress_iface_value *iface = bpf_map_lookup_elem(&egress_ifaces, &ifindex);
	if (!iface)
		return -1;
	if (((const __u32 *)iface->ipv6)[0] == 0 && ((const __u32 *)iface->ipv6)[1] == 0 &&
	    ((const __u32 *)iface->ipv6)[2] == 0 && ((const __u32 *)iface->ipv6)[3] == 0)
		return -1;
	__builtin_memcpy(host_ip, iface->ipv6, 16);
	return 0;
}

static __always_inline __u64 l4_csum_flags(const struct packet_info *pkt, __u64 extra)
{
	if (pkt->proto == IPPROTO_UDP)
		return extra | BPF_F_MARK_MANGLED_0;
	return extra;
}

static __always_inline int replace_ipv4_addr(struct __sk_buff *skb, __u32 csum_off, __u32 addr_off,
					     __u32 ip_csum_off, __be32 old_addr, __be32 new_addr,
					     int update_ip_header)
{
	if (update_ip_header &&
	    bpf_l3_csum_replace(skb, ip_csum_off, old_addr, new_addr, sizeof(old_addr)) < 0)
		return -1;
	if (bpf_l4_csum_replace(skb, csum_off, old_addr, new_addr,
				BPF_F_PSEUDO_HDR | sizeof(old_addr) | BPF_F_MARK_MANGLED_0) < 0)
		return -1;
	return bpf_skb_store_bytes(skb, addr_off, &new_addr, sizeof(new_addr), 0);
}

static __always_inline int replace_ipv4_addr_l3(struct __sk_buff *skb, __u32 addr_off,
						__u32 ip_csum_off, __be32 old_addr,
						__be32 new_addr)
{
	if (bpf_l3_csum_replace(skb, ip_csum_off, old_addr, new_addr, sizeof(old_addr)) < 0)
		return -1;
	return bpf_skb_store_bytes(skb, addr_off, &new_addr, sizeof(new_addr), 0);
}

static __always_inline int replace_ipv4_addr_for_packet(struct __sk_buff *skb,
							const struct packet_info *pkt,
							__u32 addr_off, __be32 old_addr,
							__be32 new_addr)
{
	if (pkt->proto == IPPROTO_TCP || pkt->proto == IPPROTO_UDP)
		return replace_ipv4_addr(skb, pkt->l4_csum_off, addr_off,
					 pkt->l3_off + offsetof(struct iphdr, check),
					 old_addr, new_addr, 1);
	return replace_ipv4_addr_l3(skb, addr_off, pkt->l3_off + offsetof(struct iphdr, check),
				    old_addr, new_addr);
}

static __always_inline int replace_ipv6_addr(struct __sk_buff *skb, __u32 csum_off, __u32 addr_off,
					     const __u8 old_addr[16], const __u8 new_addr[16])
{
	const __be32 *old32 = (const __be32 *)old_addr;
	const __be32 *new32 = (const __be32 *)new_addr;

	if (bpf_l4_csum_replace(skb, csum_off, old32[0], new32[0],
				BPF_F_PSEUDO_HDR | sizeof(old32[0]) | BPF_F_MARK_MANGLED_0) < 0)
		return -1;
	if (bpf_l4_csum_replace(skb, csum_off, old32[1], new32[1],
				BPF_F_PSEUDO_HDR | sizeof(old32[0]) | BPF_F_MARK_MANGLED_0) < 0)
		return -1;
	if (bpf_l4_csum_replace(skb, csum_off, old32[2], new32[2],
				BPF_F_PSEUDO_HDR | sizeof(old32[0]) | BPF_F_MARK_MANGLED_0) < 0)
		return -1;
	if (bpf_l4_csum_replace(skb, csum_off, old32[3], new32[3],
				BPF_F_PSEUDO_HDR | sizeof(old32[0]) | BPF_F_MARK_MANGLED_0) < 0)
		return -1;
	return bpf_skb_store_bytes(skb, addr_off, new_addr, 16, 0);
}

static __always_inline int replace_ipv6_addr_for_packet(struct __sk_buff *skb,
							const struct packet_info *pkt,
							__u32 addr_off,
							const __u8 old_addr[16],
							const __u8 new_addr[16])
{
	if (pkt->proto != IPPROTO_TCP && pkt->proto != IPPROTO_UDP &&
	    pkt->proto != IPPROTO_ICMPV6)
		return -1;
	return replace_ipv6_addr(skb, pkt->l4_csum_off, addr_off, old_addr, new_addr);
}

static __always_inline int replace_l4_port(struct __sk_buff *skb, const struct packet_info *pkt,
					   __u32 port_off, __be16 old_port, __be16 new_port)
{
	return bpf_l4_csum_replace(skb, pkt->l4_csum_off, old_port, new_port,
				   l4_csum_flags(pkt, sizeof(old_port))) ?:
	       bpf_skb_store_bytes(skb, port_off, &new_port, sizeof(new_port), 0);
}

static __always_inline int rewrite_dnat_v4(struct __sk_buff *skb, const struct packet_info *pkt,
					   const struct published_port_v4_value *value)
{
	__be32 new_addr = bpf_htonl(value->endpoint_ip);
	__be16 new_port = bpf_htons(value->endpoint_port);

	if (replace_ipv4_addr(skb, pkt->l4_csum_off, pkt->l3_off + offsetof(struct iphdr, daddr),
			      pkt->l3_off + offsetof(struct iphdr, check), pkt->daddr4, new_addr, 1) < 0)
		return TCX_NEXT;
	if (replace_l4_port(skb, pkt, pkt->l4_off + offsetof(struct tcphdr, dest), pkt->dport, new_port) < 0)
		return TCX_NEXT;
	if (value->ifindex != 0 && value->ifindex != skb->ifindex)
		return bpf_redirect_peer(value->ifindex, 0);
	return TCX_NEXT;
}

static __always_inline int rewrite_dnat_v6(struct __sk_buff *skb, const struct packet_info *pkt,
					   const struct published_port_v6_value *value)
{
	__be16 new_port = bpf_htons(value->endpoint_port);

	if (replace_ipv6_addr(skb, pkt->l4_csum_off, pkt->l3_off + offsetof(struct ipv6hdr, daddr),
			      pkt->daddr6.in6_u.u6_addr8, value->endpoint_ip) < 0)
		return TCX_NEXT;
	if (replace_l4_port(skb, pkt, pkt->l4_off + offsetof(struct tcphdr, dest), pkt->dport, new_port) < 0)
		return TCX_NEXT;
	if (value->ifindex != 0 && value->ifindex != skb->ifindex)
		return bpf_redirect_peer(value->ifindex, 0);
	return TCX_NEXT;
}

static __always_inline int rewrite_snat_v4(struct __sk_buff *skb, const struct packet_info *pkt,
					   const struct published_flow_v4_value *value)
{
	__be32 new_addr = bpf_htonl(value->frontend_ip);
	__be16 new_port = bpf_htons(value->frontend_port);

	netkit_dbg("snat4 %x:%d -> %x:%d", bpf_ntohl(pkt->saddr4), bpf_ntohs(pkt->sport),
		   value->frontend_ip, value->frontend_port);

	if (replace_ipv4_addr(skb, pkt->l4_csum_off, pkt->l3_off + offsetof(struct iphdr, saddr),
			      pkt->l3_off + offsetof(struct iphdr, check), pkt->saddr4, new_addr, 1) < 0)
		return TCX_NEXT;
	if (replace_l4_port(skb, pkt, pkt->l4_off + offsetof(struct tcphdr, source), pkt->sport, new_port) < 0)
		return TCX_NEXT;
	if (value->ifindex != 0 && value->ifindex != skb->ifindex)
		return bpf_redirect_neigh(value->ifindex, NULL, 0, 0);
	return TCX_NEXT;
}

static __always_inline int rewrite_snat_v6(struct __sk_buff *skb, const struct packet_info *pkt,
					   const struct published_flow_v6_value *value)
{
	__be16 new_port = bpf_htons(value->frontend_port);

	netkit_dbg("snat6 port %d -> %d", bpf_ntohs(pkt->sport), value->frontend_port);

	if (replace_ipv6_addr(skb, pkt->l4_csum_off, pkt->l3_off + offsetof(struct ipv6hdr, saddr),
			      pkt->saddr6.in6_u.u6_addr8, value->frontend_ip) < 0)
		return TCX_NEXT;
	if (replace_l4_port(skb, pkt, pkt->l4_off + offsetof(struct tcphdr, source), pkt->sport, new_port) < 0)
		return TCX_NEXT;
	if (value->ifindex != 0 && value->ifindex != skb->ifindex)
		return bpf_redirect_neigh(value->ifindex, NULL, 0, 0);
	return TCX_NEXT;
}

static __always_inline int apply_egress_snat_v4(struct __sk_buff *skb, const struct packet_info *pkt,
						__u32 host_ip)
{
	__be32 new_addr = bpf_htonl(host_ip);

	return replace_ipv4_addr_for_packet(skb, pkt, pkt->l3_off + offsetof(struct iphdr, saddr),
					    pkt->saddr4, new_addr);
}

static __always_inline int rewrite_egress_snat_v4(struct __sk_buff *skb, const struct packet_info *pkt,
						  __u32 host_ip)
{
	if (apply_egress_snat_v4(skb, pkt, host_ip) < 0)
		return TCX_NEXT;
	return TCX_NEXT;
}

static __always_inline int apply_egress_snat_v6(struct __sk_buff *skb, const struct packet_info *pkt,
						const __u8 host_ip[16])
{
	return replace_ipv6_addr_for_packet(skb, pkt, pkt->l3_off + offsetof(struct ipv6hdr, saddr),
					    pkt->saddr6.in6_u.u6_addr8, host_ip);
}

static __always_inline int rewrite_egress_snat_v6(struct __sk_buff *skb, const struct packet_info *pkt,
						  const __u8 host_ip[16])
{
	if (apply_egress_snat_v6(skb, pkt, host_ip) < 0)
		return TCX_NEXT;
	return TCX_NEXT;
}

static __always_inline int rewrite_egress_return_v4(struct __sk_buff *skb, const struct packet_info *pkt,
						    const struct egress_flow_v4_value *value)
{
	__be32 new_addr = bpf_htonl(value->endpoint_ip);

	if (replace_ipv4_addr_for_packet(skb, pkt, pkt->l3_off + offsetof(struct iphdr, daddr),
					 pkt->daddr4, new_addr) < 0)
		return TCX_NEXT;
	if (value->ifindex != 0 && value->ifindex != skb->ifindex)
		return bpf_redirect_peer(value->ifindex, 0);
	return TCX_NEXT;
}

static __always_inline int rewrite_egress_return_v6(struct __sk_buff *skb, const struct packet_info *pkt,
						    const struct egress_flow_v6_value *value)
{
	if (replace_ipv6_addr_for_packet(skb, pkt, pkt->l3_off + offsetof(struct ipv6hdr, daddr),
					 pkt->daddr6.in6_u.u6_addr8, value->endpoint_ip) < 0)
		return TCX_NEXT;
	if (value->ifindex != 0 && value->ifindex != skb->ifindex)
		return bpf_redirect_peer(value->ifindex, 0);
	return TCX_NEXT;
}

static __always_inline void remember_flow_v4(struct __sk_buff *skb, const struct packet_info *pkt,
					     const struct published_port_v4_value *value)
{
	struct published_flow_v4_key key = {
		.src_ip = value->endpoint_ip,
		.dst_ip = bpf_ntohl(pkt->saddr4),
		.src_port = value->endpoint_port,
		.dst_port = bpf_ntohs(pkt->sport),
		.proto = pkt->proto,
	};
	struct published_flow_v4_value flow = {
		.frontend_ip = bpf_ntohl(pkt->daddr4),
		.frontend_port = bpf_ntohs(pkt->dport),
		.flags = value->flags,
		.ifindex = redirect_reply_ifindex(skb->ifindex),
	};

	bpf_map_update_elem(&published_flows_v4, &key, &flow, BPF_ANY);
}

static __always_inline void remember_flow_v6(struct __sk_buff *skb, const struct packet_info *pkt,
					     const struct published_port_v6_value *value)
{
	struct published_flow_v6_key key = {
		.src_port = value->endpoint_port,
		.dst_port = bpf_ntohs(pkt->sport),
		.proto = pkt->proto,
	};
	struct published_flow_v6_value flow = {
		.frontend_port = bpf_ntohs(pkt->dport),
		.flags = value->flags,
		.ifindex = redirect_reply_ifindex(skb->ifindex),
	};

	__builtin_memcpy(key.src_ip, value->endpoint_ip, sizeof(key.src_ip));
	__builtin_memcpy(key.dst_ip, pkt->saddr6.in6_u.u6_addr8, sizeof(key.dst_ip));
	__builtin_memcpy(flow.frontend_ip, pkt->daddr6.in6_u.u6_addr8, sizeof(flow.frontend_ip));
	bpf_map_update_elem(&published_flows_v6, &key, &flow, BPF_ANY);
}

static __always_inline int lookup_flow_v4(const struct packet_info *pkt,
					  const struct published_flow_v4_value **value)
{
	struct published_flow_v4_key key = {
		.src_ip = bpf_ntohl(pkt->saddr4),
		.dst_ip = bpf_ntohl(pkt->daddr4),
		.src_port = bpf_ntohs(pkt->sport),
		.dst_port = bpf_ntohs(pkt->dport),
		.proto = pkt->proto,
	};

	*value = bpf_map_lookup_elem(&published_flows_v4, &key);
	return *value ? 0 : -1;
}

static __always_inline int lookup_flow_v6(const struct packet_info *pkt,
					  const struct published_flow_v6_value **value)
{
	struct published_flow_v6_key key = {
		.src_port = bpf_ntohs(pkt->sport),
		.dst_port = bpf_ntohs(pkt->dport),
		.proto = pkt->proto,
	};

	__builtin_memcpy(key.src_ip, pkt->saddr6.in6_u.u6_addr8, sizeof(key.src_ip));
	__builtin_memcpy(key.dst_ip, pkt->daddr6.in6_u.u6_addr8, sizeof(key.dst_ip));
	*value = bpf_map_lookup_elem(&published_flows_v6, &key);
	return *value ? 0 : -1;
}

static __always_inline void remember_egress_flow_v4(const struct packet_info *pkt, __u32 host_ip,
						    __u32 ifindex)
{
	struct egress_flow_v4_key key = {
		.src_ip = bpf_ntohl(pkt->daddr4),
		.dst_ip = host_ip,
		.src_port = bpf_ntohs(pkt->dport),
		.dst_port = bpf_ntohs(pkt->sport),
		.proto = pkt->proto,
	};
	struct egress_flow_v4_value value = {
		.endpoint_ip = bpf_ntohl(pkt->saddr4),
		.ifindex = ifindex,
	};

	bpf_map_update_elem(&egress_flows_v4, &key, &value, BPF_ANY);
}

static __always_inline void remember_egress_flow_v6(const struct packet_info *pkt, const __u8 host_ip[16],
						    __u32 ifindex)
{
	struct egress_flow_v6_key key = {
		.src_port = bpf_ntohs(pkt->dport),
		.dst_port = bpf_ntohs(pkt->sport),
		.proto = pkt->proto,
	};
	struct egress_flow_v6_value value = {};

	__builtin_memcpy(key.src_ip, pkt->daddr6.in6_u.u6_addr8, sizeof(key.src_ip));
	__builtin_memcpy(key.dst_ip, host_ip, sizeof(key.dst_ip));
	__builtin_memcpy(value.endpoint_ip, pkt->saddr6.in6_u.u6_addr8, sizeof(value.endpoint_ip));
	value.ifindex = ifindex;
	bpf_map_update_elem(&egress_flows_v6, &key, &value, BPF_ANY);
}

static __always_inline int host_netns_only(void *ctx)
{
	if (host_netns_cookie == 0)
		return 1;
	return bpf_get_netns_cookie(ctx) == host_netns_cookie;
}

static __always_inline void remember_sock_v4(struct bpf_sock_addr *ctx,
					     const struct published_port_v4_value *value)
{
	__u64 cookie = bpf_get_socket_cookie(ctx);
	struct published_sock_v4_value state;

	if (cookie == 0 || ctx->protocol != IPPROTO_TCP)
		return;

	__builtin_memset(&state, 0, sizeof(state));
	state.frontend_ip = bpf_ntohl(ctx->user_ip4);
	state.frontend_port = bpf_ntohs((__be16)ctx->user_port);
	state.backend_ip = value->endpoint_ip;
	state.backend_port = value->endpoint_port;
	state.proto = ctx->protocol;
	state.flags = value->flags;
	bpf_map_update_elem(&published_sock_v4, &cookie, &state, BPF_ANY);
}

static __always_inline void remember_sock_v6(struct bpf_sock_addr *ctx,
					     const struct published_port_v6_value *value)
{
	__u64 cookie = bpf_get_socket_cookie(ctx);
	struct published_sock_v6_value state = {
		.frontend_port = bpf_ntohs((__be16)ctx->user_port),
		.backend_port = value->endpoint_port,
		.proto = ctx->protocol,
		.flags = value->flags,
	};

	if (cookie == 0 || ctx->protocol != IPPROTO_TCP)
		return;

	((__u32 *)state.frontend_ip)[0] = ctx->user_ip6[0];
	((__u32 *)state.frontend_ip)[1] = ctx->user_ip6[1];
	((__u32 *)state.frontend_ip)[2] = ctx->user_ip6[2];
	((__u32 *)state.frontend_ip)[3] = ctx->user_ip6[3];
	__builtin_memcpy(state.backend_ip, value->endpoint_ip, sizeof(state.backend_ip));
	bpf_map_update_elem(&published_sock_v6, &cookie, &state, BPF_ANY);
}

static __always_inline int rewrite_sock_v4(struct bpf_sock_addr *ctx, int remember)
{
	const struct published_port_v4_value *value;

	if (!host_netns_only(ctx))
		return 1;
	if (ctx->protocol != IPPROTO_TCP && ctx->protocol != IPPROTO_UDP)
		return 1;
	if (lookup_sock_published_port_v4(ctx, &value) < 0)
		return 1;

	if (remember)
		remember_sock_v4(ctx, value);
	ctx->user_ip4 = bpf_htonl(value->endpoint_ip);
	ctx->user_port = bpf_htons(value->endpoint_port);
	return 1;
}

static __always_inline int rewrite_sock_v6(struct bpf_sock_addr *ctx, int remember)
{
	const struct published_port_v6_value *value;

	if (!host_netns_only(ctx))
		return 1;
	if (ctx->protocol != IPPROTO_TCP && ctx->protocol != IPPROTO_UDP)
		return 1;
	if (lookup_sock_published_port_v6(ctx, &value) < 0)
		return 1;

	if (remember)
		remember_sock_v6(ctx, value);
	ctx->user_ip6[0] = ((__u32 *)value->endpoint_ip)[0];
	ctx->user_ip6[1] = ((__u32 *)value->endpoint_ip)[1];
	ctx->user_ip6[2] = ((__u32 *)value->endpoint_ip)[2];
	ctx->user_ip6[3] = ((__u32 *)value->endpoint_ip)[3];
	ctx->user_port = bpf_htons(value->endpoint_port);
	return 1;
}

static __always_inline int rewrite_getpeername_v4(struct bpf_sock_addr *ctx)
{
	__u64 cookie;
	const struct published_sock_v4_value *state;

	if (!host_netns_only(ctx))
		return 1;
	cookie = bpf_get_socket_cookie(ctx);
	if (cookie == 0)
		return 1;

	state = bpf_map_lookup_elem(&published_sock_v4, &cookie);
	if (!state)
		return 1;

	ctx->user_ip4 = bpf_htonl(state->frontend_ip);
	ctx->user_port = bpf_htons(state->frontend_port);
	return 1;
}

static __always_inline int rewrite_getpeername_v6(struct bpf_sock_addr *ctx)
{
	__u64 cookie;
	const struct published_sock_v6_value *state;

	if (!host_netns_only(ctx))
		return 1;
	cookie = bpf_get_socket_cookie(ctx);
	if (cookie == 0)
		return 1;

	state = bpf_map_lookup_elem(&published_sock_v6, &cookie);
	if (!state)
		return 1;

	ctx->user_ip6[0] = ((__u32 *)state->frontend_ip)[0];
	ctx->user_ip6[1] = ((__u32 *)state->frontend_ip)[1];
	ctx->user_ip6[2] = ((__u32 *)state->frontend_ip)[2];
	ctx->user_ip6[3] = ((__u32 *)state->frontend_ip)[3];
	ctx->user_port = bpf_htons(state->frontend_port);
	return 1;
}

static __always_inline int process_published_ingress(struct __sk_buff *skb)
{
	struct packet_info pkt = {};

	if (parse_packet(skb, &pkt) < 0)
		return TCX_NEXT;

	if (pkt.family == AF_INET) {
		const struct published_flow_v4_value *flow;
		const struct published_port_v4_value *value;

		if (lookup_flow_v4(&pkt, &flow) == 0)
			return rewrite_snat_v4(skb, &pkt, flow);
		if (lookup_published_port_v4(&pkt, &value) < 0)
			return TCX_NEXT;

		netkit_dbg("dnat4 hit %x:%d -> %x:%d", bpf_ntohl(pkt.daddr4), bpf_ntohs(pkt.dport),
			   value->endpoint_ip, value->endpoint_port);
		remember_flow_v4(skb, &pkt, value);
		return rewrite_dnat_v4(skb, &pkt, value);
	}

	if (pkt.family == AF_INET6) {
		const struct published_flow_v6_value *flow;
		const struct published_port_v6_value *value;

		if (lookup_flow_v6(&pkt, &flow) == 0)
			return rewrite_snat_v6(skb, &pkt, flow);
		if (lookup_published_port_v6(&pkt, &value) < 0)
			return TCX_NEXT;

		netkit_dbg("dnat6 hit port %d -> %d", bpf_ntohs(pkt.dport), value->endpoint_port);
		remember_flow_v6(skb, &pkt, value);
		return rewrite_dnat_v6(skb, &pkt, value);
	}

	return TCX_NEXT;
}

static __always_inline int match_published_v4(const struct packet_info *pkt)
{
	const struct published_flow_v4_value *flow;
	const struct published_port_v4_value *value;

	if (lookup_flow_v4(pkt, &flow) == 0)
		return 1;
	return lookup_published_port_v4(pkt, &value) == 0;
}

static __always_inline int match_published_v6(const struct packet_info *pkt)
{
	const struct published_flow_v6_value *flow;
	const struct published_port_v6_value *value;

	if (lookup_flow_v6(pkt, &flow) == 0)
		return 1;
	return lookup_published_port_v6(pkt, &value) == 0;
}

static __always_inline int process_published_egress(struct __sk_buff *skb)
{
	struct packet_info pkt = {};

	if (parse_packet(skb, &pkt) < 0) {
		netkit_dbg("egress parse fail proto=%d", bpf_ntohs(skb->protocol));
		return TCX_NEXT;
	}

	if (pkt.family == AF_INET)
		netkit_dbg("egress4 tuple %x:%d -> %x:%d", bpf_ntohl(pkt.saddr4), bpf_ntohs(pkt.sport),
			   bpf_ntohl(pkt.daddr4), bpf_ntohs(pkt.dport));
	else if (pkt.family == AF_INET6)
		netkit_dbg("egress6 tuple %d -> %d", bpf_ntohs(pkt.sport), bpf_ntohs(pkt.dport));

	if (pkt.family == AF_INET) {
		const struct published_flow_v4_value *flow;

		if (lookup_flow_v4(&pkt, &flow) < 0) {
			netkit_dbg("egress4 miss %x:%d -> %x:%d", bpf_ntohl(pkt.saddr4), bpf_ntohs(pkt.sport),
				   bpf_ntohl(pkt.daddr4), bpf_ntohs(pkt.dport));
			return TCX_NEXT;
		}

		return rewrite_snat_v4(skb, &pkt, flow);
	}

	if (pkt.family == AF_INET6) {
		const struct published_flow_v6_value *flow;

		if (lookup_flow_v6(&pkt, &flow) < 0) {
			netkit_dbg("egress6 miss %d -> %d", bpf_ntohs(pkt.sport), bpf_ntohs(pkt.dport));
			return TCX_NEXT;
		}

		return rewrite_snat_v6(skb, &pkt, flow);
	}

	return TCX_NEXT;
}

static __always_inline int process_host_facing_ingress(struct __sk_buff *skb)
{
	struct packet_info pkt = {};

	if (parse_packet(skb, &pkt) < 0)
		return TCX_NEXT;

	if (pkt.family == AF_INET) {
		const struct egress_flow_v4_value *flow;

		if (lookup_egress_flow_v4(&pkt, &flow) == 0) {
			netkit_dbg("host ingress flow4 hit");
			return rewrite_egress_return_v4(skb, &pkt, flow);
		}
	}

	if (pkt.family == AF_INET6) {
		const struct egress_flow_v6_value *flow;

		if (lookup_egress_flow_v6(&pkt, &flow) == 0)
			return rewrite_egress_return_v6(skb, &pkt, flow);
	}

	return process_published_ingress(skb);
}

static __always_inline int process_internal_ingress(struct __sk_buff *skb)
{
	return process_published_ingress(skb);
}

/*
 * Do not read skb->ifindex from this helper.
 *
 * We hit a real verifier rejection on an earlier version of this path:
 *
 *   dereference of modified ctx ptr R6 off=40 disallowed
 *
 * off=40 (0x28) is struct __sk_buff::ifindex.
 *
 * The "late read" variant emitted another ctx load here:
 *
 *   792: if r1 == 0x0 goto ...
 *   793: w2 = *(u32 *)(r6 + 0x28)
 *   794: *(u32 *)(r10 - 0x28) = w2
 *   800: call bpf_map_lookup_elem(&egress_ifaces, &ifindex)
 *
 * The current shape reuses the scalar captured at the tc entrypoint instead:
 *
 *   portmap_egress:
 *     0: r6 = r1
 *     1: w7 = *(u32 *)(r6 + 0x28)
 *   ...
 *   near resolve_egress_ipv4():
 *   793: if r1 == 0x0 goto ...
 *   794: *(u32 *)(r10 - 0x28) = w7
 *   800: call bpf_map_lookup_elem(&egress_ifaces, &ifindex)
 *
 * Passing ifindex down as a plain scalar keeps this helper on normal
 * stack/scalar state and avoids a second ctx-field load in the deep egress
 * path.
 */
static __always_inline int process_host_facing_egress(struct __sk_buff *skb, __u32 ifindex)
{
	struct packet_info pkt = {};

	if (parse_packet(skb, &pkt) < 0)
		return TCX_NEXT;

	if (pkt.family == AF_INET) {
		const struct published_flow_v4_value *published;
		const struct egress_endpoint_v4_value *endpoint;
		__u32 host_ip;

		netkit_dbg("host egress4 tuple %x:%d -> %x:%d", bpf_ntohl(pkt.saddr4), bpf_ntohs(pkt.sport),
			   bpf_ntohl(pkt.daddr4), bpf_ntohs(pkt.dport));
		if (lookup_flow_v4(&pkt, &published) == 0)
			return rewrite_snat_v4(skb, &pkt, published);
		if (lookup_egress_endpoint_v4(&pkt, &endpoint) < 0) {
			netkit_dbg("host egress4 endpoint miss src=%x", bpf_ntohl(pkt.saddr4));
			return TCX_NEXT;
		}
		if (resolve_egress_ipv4(ifindex, endpoint, &host_ip) < 0) {
			netkit_dbg("host egress4 resolve miss if=%d", ifindex);
			return TCX_NEXT;
		}

		netkit_dbg("host egress4 snat host=%x", host_ip);
		if (apply_egress_snat_v4(skb, &pkt, host_ip) < 0)
			return TCX_NEXT;
		remember_egress_flow_v4(&pkt, host_ip, 0);
		return TCX_NEXT;
	}

	if (pkt.family == AF_INET6) {
		const struct published_flow_v6_value *published;
		const struct egress_endpoint_v6_value *endpoint;
		__u8 host_ip[16];

		if (lookup_flow_v6(&pkt, &published) == 0)
			return rewrite_snat_v6(skb, &pkt, published);
		if (lookup_egress_endpoint_v6(&pkt, &endpoint) < 0)
			return TCX_NEXT;
		if (resolve_egress_ipv6(ifindex, endpoint, host_ip) < 0)
			return TCX_NEXT;

		if (apply_egress_snat_v6(skb, &pkt, host_ip) < 0)
			return TCX_NEXT;
		remember_egress_flow_v6(&pkt, host_ip, 0);
		return TCX_NEXT;
	}

	return TCX_NEXT;
}

static __always_inline int redirect_endpoint_egress_v4(struct __sk_buff *skb,
						       const struct packet_info *pkt,
						       const struct egress_endpoint_v4_value *endpoint)
{
	struct bpf_redir_neigh neigh = {};
	struct bpf_fib_lookup fib = {};
	__u32 host_ip;
	long ret;

	fib.family = AF_INET;
	fib.l4_protocol = pkt->proto;
	fib.sport = pkt->sport;
	fib.dport = pkt->dport;
	fib.tot_len = pkt->l3_len;
	fib.ifindex = skb->ifindex;
	fib.tos = pkt->tos;
	fib.ipv4_src = pkt->saddr4;
	fib.ipv4_dst = pkt->daddr4;

	ret = bpf_fib_lookup(skb, &fib, sizeof(fib), BPF_FIB_LOOKUP_SKIP_NEIGH);
	if (ret != BPF_FIB_LKUP_RET_SUCCESS) {
		netkit_dbg("endpoint egress4 fib miss ret=%ld src=%x dst=%x if=%d", ret,
			   bpf_ntohl(pkt->saddr4), bpf_ntohl(pkt->daddr4), skb->ifindex);
		return TCX_NEXT;
	}
	if (resolve_egress_ipv4(fib.ifindex, endpoint, &host_ip) < 0) {
		netkit_dbg("endpoint egress4 resolve miss out_if=%d", fib.ifindex);
		return TCX_NEXT;
	}

	if (apply_egress_snat_v4(skb, pkt, host_ip) < 0) {
		netkit_dbg("endpoint egress4 snat fail host=%x out_if=%d", host_ip, fib.ifindex);
		return TCX_NEXT;
	}
	remember_egress_flow_v4(pkt, host_ip, endpoint->ifindex);

	neigh.nh_family = AF_INET;
	neigh.ipv4_nh = fib.ipv4_dst;
	netkit_dbg("endpoint egress4 redirect host=%x out_if=%d nh=%x", host_ip, fib.ifindex,
		   bpf_ntohl(fib.ipv4_dst));
	return bpf_redirect_neigh(fib.ifindex, &neigh, sizeof(neigh), 0);
}

static __always_inline int redirect_endpoint_egress_v6(struct __sk_buff *skb,
						       const struct packet_info *pkt,
						       const struct egress_endpoint_v6_value *endpoint)
{
	struct bpf_redir_neigh neigh = {};
	struct bpf_fib_lookup fib = {};
	__u8 host_ip[16];
	long ret;

	fib.family = AF_INET6;
	fib.l4_protocol = pkt->proto;
	fib.sport = pkt->sport;
	fib.dport = pkt->dport;
	fib.tot_len = pkt->l3_len;
	fib.ifindex = skb->ifindex;
	__builtin_memcpy(fib.ipv6_src, pkt->saddr6.in6_u.u6_addr32, sizeof(fib.ipv6_src));
	__builtin_memcpy(fib.ipv6_dst, pkt->daddr6.in6_u.u6_addr32, sizeof(fib.ipv6_dst));

	ret = bpf_fib_lookup(skb, &fib, sizeof(fib), BPF_FIB_LOOKUP_SKIP_NEIGH);
	if (ret != BPF_FIB_LKUP_RET_SUCCESS) {
		netkit_dbg("endpoint egress6 fib miss ret=%ld if=%d", ret, skb->ifindex);
		return TCX_NEXT;
	}
	if (resolve_egress_ipv6(fib.ifindex, endpoint, host_ip) < 0) {
		netkit_dbg("endpoint egress6 resolve miss out_if=%d", fib.ifindex);
		return TCX_NEXT;
	}

	if (apply_egress_snat_v6(skb, pkt, host_ip) < 0) {
		netkit_dbg("endpoint egress6 snat fail out_if=%d", fib.ifindex);
		return TCX_NEXT;
	}
	remember_egress_flow_v6(pkt, host_ip, endpoint->ifindex);

	neigh.nh_family = AF_INET6;
	__builtin_memcpy(neigh.ipv6_nh, fib.ipv6_dst, sizeof(neigh.ipv6_nh));
	netkit_dbg("endpoint egress6 redirect out_if=%d", fib.ifindex);
	return bpf_redirect_neigh(fib.ifindex, &neigh, sizeof(neigh), 0);
}

static __always_inline int process_endpoint_egress(struct __sk_buff *skb)
{
	struct packet_info pkt = {};
	int ret;

	if (parse_packet(skb, &pkt) < 0)
		return TCX_NEXT;

	ret = redirect_local_endpoint(skb, &pkt);
	if (ret != TCX_NEXT)
		return ret;

	if (pkt.family == AF_INET) {
		const struct egress_endpoint_v4_value *endpoint;

		if (lookup_egress_endpoint_v4(&pkt, &endpoint) < 0) {
			netkit_dbg("endpoint egress4 endpoint miss src=%x", bpf_ntohl(pkt.saddr4));
			return TCX_NEXT;
		}
		return redirect_endpoint_egress_v4(skb, &pkt, endpoint);
	}

	if (pkt.family == AF_INET6) {
		const struct egress_endpoint_v6_value *endpoint;

		if (lookup_egress_endpoint_v6(&pkt, &endpoint) < 0) {
			netkit_dbg("endpoint egress6 endpoint miss");
			return TCX_NEXT;
		}
		return redirect_endpoint_egress_v6(skb, &pkt, endpoint);
	}

	return TCX_NEXT;
}

static __always_inline int tcx_to_netkit_action(int action)
{
	if (action == TCX_NEXT)
		return NETKIT_PASS;
	return action;
}

SEC("tcx/ingress")
int portmap_ingress(struct __sk_buff *skb)
{
	__u32 ifindex = skb->ifindex;
	int host_facing = iface_is_host_facing(ifindex);

	netkit_dbg("ingress ifindex=%d host=%d", ifindex, host_facing);
	if (host_facing)
		return process_host_facing_ingress(skb);
	return process_internal_ingress(skb);
}

SEC("tcx/egress")
int portmap_egress(struct __sk_buff *skb)
{
	/*
	 * Cache ifindex at the tc entrypoint and pass it as a scalar.
	 *
	 * The intended codegen is:
	 *   0: r6 = r1
	 *   1: w7 = *(u32 *)(r6 + 0x28)
	 *
	 * so the deep egress path can reuse w7 instead of emitting another
	 * "*(u32 *)(ctx + 0x28)" load around resolve_egress_ipv4/ipv6().
	 */
	__u32 ifindex = skb->ifindex;
	int host_facing = iface_is_host_facing(ifindex);

	netkit_dbg("egress ifindex=%d host=%d", ifindex, host_facing);
	if (host_facing)
		return process_host_facing_egress(skb, ifindex);
	return process_published_egress(skb);
}

SEC("netkit/primary")
int endpoint_primary(struct __sk_buff *skb)
{
	return tcx_to_netkit_action(process_published_ingress(skb));
}

SEC("netkit/peer")
int endpoint_peer(struct __sk_buff *skb)
{
	int ret = process_published_egress(skb);

	if (ret != TCX_NEXT)
		return tcx_to_netkit_action(ret);
	return tcx_to_netkit_action(process_endpoint_egress(skb));
}

SEC("cgroup/connect4")
int connect4(struct bpf_sock_addr *ctx)
{
	return rewrite_sock_v4(ctx, 1);
}

SEC("cgroup/connect6")
int connect6(struct bpf_sock_addr *ctx)
{
	return rewrite_sock_v6(ctx, 1);
}

SEC("cgroup/sendmsg4")
int sendmsg4(struct bpf_sock_addr *ctx)
{
	return rewrite_sock_v4(ctx, 0);
}

SEC("cgroup/sendmsg6")
int sendmsg6(struct bpf_sock_addr *ctx)
{
	return rewrite_sock_v6(ctx, 0);
}

SEC("cgroup/getpeername4")
int getpeername4(struct bpf_sock_addr *ctx)
{
	return rewrite_getpeername_v4(ctx);
}

SEC("cgroup/getpeername6")
int getpeername6(struct bpf_sock_addr *ctx)
{
	return rewrite_getpeername_v6(ctx);
}

char LICENSE[] SEC("license") = "GPL";
