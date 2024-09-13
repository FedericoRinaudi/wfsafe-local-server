#ifndef __HEADER_PARSER_H
#define __HEADER_PARSER_H

#include "vmlinux.h"

#define ETH_HLEN 14
#define ETH_P_IP 0x0800
#define IPV4_MIN_HLEN 20
#define TCP_MIN_HLEN 20

static __always_inline int ip_is_fragment(struct iphdr *iph)
{
	return bpf_ntohs(iph->frag_off) & (IP_MF | IP_OFFSET);
}

static __always_inline struct ethhdr *parse_ethernet(struct xdp_md *ctx)
{
	struct ethhdr *eth = ptr_at(ctx, 0, sizeof(struct ethhdr));
	if (!eth)
		return NULL;
	if (bpf_htons(eth->h_proto) != ETH_P_IP)
		return NULL;
	return eth;

}

static __always_inline struct iphdr *parse_ip(struct xdp_md *ctx)
{
	struct iphdr *iph;
	iph = ptr_at(ctx, ETH_HLEN, sizeof(struct iphdr));
	if (!iph)
		return NULL;

	if (ip_is_fragment(iph))
		return NULL;
	
	if (iph->protocol != IPPROTO_TCP)
		return NULL;
	
	return iph;
}

static __always_inline struct tcphdr *parse_tcp(struct xdp_md *ctx, __u8 ip_len)
{
	__u8 tcp_offset = ETH_HLEN + ip_len;
	struct tcphdr *tcph;
	if(tcp_offset == 34)
		tcph = ptr_at(ctx, 34, sizeof(struct tcphdr));
	else if (tcp_offset == 38)
		tcph = ptr_at(ctx, 38, sizeof(struct tcphdr));
	else if (tcp_offset == 42)
		tcph = ptr_at(ctx, 42, sizeof(struct tcphdr));
	else if (tcp_offset == 46)
	    tcph = ptr_at(ctx, 46, sizeof(struct tcphdr));
	else if (tcp_offset == 50)
		tcph = ptr_at(ctx, 50, sizeof(struct tcphdr));
	else if (tcp_offset == 54)
		tcph = ptr_at(ctx, 54, sizeof(struct tcphdr));
	else if (tcp_offset == 58)
		tcph = ptr_at(ctx, 58, sizeof(struct tcphdr));
	else if (tcp_offset == 62)
		tcph = ptr_at(ctx, 62, sizeof(struct tcphdr));
	else if (tcp_offset == 66)
		tcph = ptr_at(ctx, 66, sizeof(struct tcphdr));
	else if (tcp_offset == 70)
		tcph = ptr_at(ctx, 70, sizeof(struct tcphdr));
	else if (tcp_offset == 74)
		tcph = ptr_at(ctx, 74, sizeof(struct tcphdr));
	else 
		tcph = NULL;
	if (!tcph)
		return NULL;
	return tcph;
}

#endif