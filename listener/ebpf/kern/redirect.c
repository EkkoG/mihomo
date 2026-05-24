// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2026, mihomo

// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TPROXY_MARK 0x8000000
#define ETH_HDR_LEN 14
#define BPF_TCP_LISTEN 10

// ---- Param (injected from userspace) ----

struct ebpf_param {
	__u32 tproxy_port;
	__u32 tproxy_mark;
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct ebpf_param);
	__uint(max_entries, 1);
} param_map SEC(".maps");

// ---- Bypass LPM tries ----

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, __u32[5]);  // prefixlen(4) + IPv6-mapped IPv4 addr(16)
	__type(value, __u8);
	__uint(max_entries, 65536);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} bypass_v4_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, __u32[5]);  // prefixlen(4) + IPv6 addr(16)
	__type(value, __u8);
	__uint(max_entries, 65536);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} bypass_v6_map SEC(".maps");

// ---- Handoff metadata (eBPF -> userspace) ----

struct handoff_key {
	__be32 sip[4];
	__be32 dip[4];
	__be16 sport;
	__be16 dport;
	__u8  l4proto;
	__u8  pad[3];
} __attribute__((packed));

struct handoff_entry {
	__u8  smac[6];
	__u8  dmac[6];
	__u32 ifindex;
	__u64 timestamp;
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct handoff_key);
	__type(value, struct handoff_entry);
	__uint(max_entries, 65536);
} handoff_map SEC(".maps");

// ---- Packet parse context ----

struct packet_ctx {
	__u8  smac[6];
	__u8  dmac[6];
	__u16 l3proto;
	__u8  l4proto;
	__be32 sip[4];
	__be32 dip[4];
	__be16 sport;
	__be16 dport;
	__u16 l3off;
};

// ---- Parse helpers ----

static __always_inline int parse_eth(struct __sk_buff *skb, struct packet_ctx *ctx)
{
	if (bpf_skb_load_bytes(skb, 0, &ctx->dmac, 12) < 0)
		return -1;

	__be16 proto;
	if (bpf_skb_load_bytes(skb, 12, &proto, 2) < 0)
		return -1;

	ctx->l3proto = proto;
	ctx->l3off = ETH_HDR_LEN;

	if (bpf_skb_load_bytes(skb, 6, ctx->smac, 6) < 0)
		return -1;

	return 0;
}

static __always_inline int parse_ip(struct __sk_buff *skb, struct packet_ctx *ctx)
{
	if (ctx->l3proto == bpf_htons(ETH_P_IP)) {
		struct iphdr ip4;
		if (bpf_skb_load_bytes(skb, ctx->l3off, &ip4, sizeof(ip4)) < 0)
			return -1;

		ctx->l4proto = ip4.protocol;
		ctx->sip[2] = bpf_htonl(0x0000ffff);
		ctx->sip[3] = ip4.saddr;
		ctx->dip[2] = bpf_htonl(0x0000ffff);
		ctx->dip[3] = ip4.daddr;

		ctx->l3off += ip4.ihl * 4;
	} else if (ctx->l3proto == bpf_htons(ETH_P_IPV6)) {
		__u8 ip6buf[40];
		if (bpf_skb_load_bytes(skb, ctx->l3off, ip6buf, 40) < 0)
			return -1;

		ctx->l4proto = ip6buf[6]; // next header

		for (int i = 0; i < 4; i++) {
			ctx->sip[i] = *((__be32 *)(ip6buf + 8 + i * 4));
			ctx->dip[i] = *((__be32 *)(ip6buf + 24 + i * 4));
		}

		// Skip extension headers to find L4
		__u8 nh = ctx->l4proto;
		__u16 ext_off = ctx->l3off + 40;
		for (int i = 0; i < 4; i++) {
			if (nh == IPPROTO_TCP || nh == IPPROTO_UDP)
				break;
			if (nh != 0 && nh != 43 && nh != 44 && nh != 51 && nh != 60 && nh != 135)
				return 0;

			__u8 ext[2];
			if (bpf_skb_load_bytes(skb, ext_off, ext, 2) < 0)
				return -1;

			nh = ext[0];
			ext_off += (__u16)(ext[1] + 1) * 8;
		}
		ctx->l4proto = nh;
		ctx->l3off = ext_off;
	} else {
		return 0;
	}

	return 0;
}

static __always_inline int parse_l4(struct __sk_buff *skb, struct packet_ctx *ctx)
{
	__u8 ports[4];
	if (bpf_skb_load_bytes(skb, ctx->l3off, ports, 4) < 0)
		return -1;

	ctx->sport = *((__be16 *)&ports[0]);
	ctx->dport = *((__be16 *)&ports[2]);

	return 0;
}

// ---- Bypass LPM key builders ----

static __always_inline void build_lpm_v4_key(const __be32 dip, __u32 *key)
{
	key[0] = 32;
	key[1] = 0;
	key[2] = 0;
	key[3] = 0x0000ffff;
	key[4] = dip;
}

static __always_inline void build_lpm_v6_key(const __be32 *dip, __u32 *key)
{
	key[0] = 128;
	key[1] = dip[0];
	key[2] = dip[1];
	key[3] = dip[2];
	key[4] = dip[3];
}

// ---- Socket-based traffic classification ----
// Reference: dae's do_tproxy_lan_ingress socket lookup logic.
//
// For TCP: bpf_skc_lookup_tcp finds sockets matching the destination tuple.
//   - LISTEN socket → local service accepting connections → pass through.
//   - established socket → reply/established traffic → pass through.
//   - no socket → new connection to external IP → redirect.
//
// For UDP: bpf_sk_lookup_udp finds sockets matching the destination tuple.
//   - any socket → existing flow or local service → pass through.
//   - no socket → new flow → redirect.

static __always_inline int classify_by_socket(struct __sk_buff *skb, struct packet_ctx *pkt)
{
	struct bpf_sock_tuple tuple = {};
	__u32 tuple_size;

	if (pkt->l3proto == bpf_htons(ETH_P_IP)) {
		tuple.ipv4.daddr = pkt->dip[3];
		tuple.ipv4.saddr = pkt->sip[3];
		tuple.ipv4.dport = pkt->dport;
		tuple.ipv4.sport = pkt->sport;
		tuple_size = sizeof(tuple.ipv4);
	} else {
		__builtin_memcpy(tuple.ipv6.daddr, pkt->dip, 16);
		__builtin_memcpy(tuple.ipv6.saddr, pkt->sip, 16);
		tuple.ipv6.dport = pkt->dport;
		tuple.ipv6.sport = pkt->sport;
		tuple_size = sizeof(tuple.ipv6);
	}

	if (pkt->l4proto == IPPROTO_TCP) {
		struct bpf_sock *sk =
			bpf_skc_lookup_tcp(skb, &tuple, tuple_size, 0, 0);
		if (sk) {
			// LISTEN: local service (web server, etc.) → pass through
			// non-LISTEN: established connection (mihomo's own traffic,
			//   existing NAT flows, reply packets) → pass through
			bpf_sk_release(sk);
			return 0; // pass through
		}
		// No socket → new outbound connection → redirect
		return 1;
	}

	if (pkt->l4proto == IPPROTO_UDP) {
		struct bpf_sock *sk =
			bpf_sk_lookup_udp(skb, &tuple, sizeof(tuple), 0, 0);
		if (sk) {
			// Existing socket (local service, established flow, reply)
			bpf_sk_release(sk);
			return 0; // pass through
		}
		return 1; // new flow → redirect
	}

	return 0; // unknown protocol
}

// ---- Store metadata for userspace ----

static __always_inline void store_handoff(struct __sk_buff *skb, struct packet_ctx *pkt)
{
	struct handoff_key hkey = {};
	hkey.sip[0] = pkt->sip[0];
	hkey.sip[1] = pkt->sip[1];
	hkey.sip[2] = pkt->sip[2];
	hkey.sip[3] = pkt->sip[3];
	hkey.dip[0] = pkt->dip[0];
	hkey.dip[1] = pkt->dip[1];
	hkey.dip[2] = pkt->dip[2];
	hkey.dip[3] = pkt->dip[3];
	hkey.sport = pkt->sport;
	hkey.dport = pkt->dport;
	hkey.l4proto = pkt->l4proto;

	struct handoff_entry entry = {};
	__builtin_memcpy(entry.smac, pkt->smac, 6);
	__builtin_memcpy(entry.dmac, pkt->dmac, 6);
	entry.ifindex = skb->ifindex;
	entry.timestamp = bpf_ktime_get_ns();

	bpf_map_update_elem(&handoff_map, &hkey, &entry, BPF_ANY);
}

// ---- TC ingress program ----

SEC("tc/ebpf_ingress")
int ebpf_ingress(struct __sk_buff *skb)
{
	struct packet_ctx pkt = {};
	int ret;

	// 1. Parse Ethernet
	ret = parse_eth(skb, &pkt);
	if (ret < 0)
		goto pass;

	// 2. Only IP
	if (pkt.l3proto != bpf_htons(ETH_P_IP) && pkt.l3proto != bpf_htons(ETH_P_IPV6))
		goto pass;

	// 3. Parse IP
	ret = parse_ip(skb, &pkt);
	if (ret < 0)
		goto pass;

	// 4. Check bypass LPM
	__u32 lpm_key[5];
	__u8 *bypass_val;
	if (pkt.l3proto == bpf_htons(ETH_P_IP)) {
		build_lpm_v4_key(pkt.dip[3], lpm_key);
		bypass_val = bpf_map_lookup_elem(&bypass_v4_map, lpm_key);
	} else {
		build_lpm_v6_key(pkt.dip, lpm_key);
		bypass_val = bpf_map_lookup_elem(&bypass_v6_map, lpm_key);
	}
	if (bypass_val)
		goto pass;

	// 5. Only TCP and UDP
	if (pkt.l4proto != IPPROTO_TCP && pkt.l4proto != IPPROTO_UDP)
		goto pass;

	// 6. Parse L4 ports
	ret = parse_l4(skb, &pkt);
	if (ret < 0)
		goto pass;

	// 7. Socket-based classification:
	//    - Local service (LISTEN) or established flow → pass through
	//    - New external connection → redirect
	if (!classify_by_socket(skb, &pkt))
		goto pass;

	// 8. Store metadata for userspace enrichment
	store_handoff(skb, &pkt);

	// 9. Set TPROXY mark and redirect to loopback
	skb->mark = TPROXY_MARK;
	return bpf_redirect(1, 0);

pass:
	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
