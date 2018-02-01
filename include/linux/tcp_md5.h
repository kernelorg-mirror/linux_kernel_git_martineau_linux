/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_TCP_MD5_H
#define _LINUX_TCP_MD5_H

#include <linux/skbuff.h>

#ifdef CONFIG_TCP_MD5SIG
#include <linux/types.h>

#include <net/tcp.h>

union tcp_md5_addr {
	struct in_addr  a4;
#if IS_ENABLED(CONFIG_IPV6)
	struct in6_addr	a6;
#endif
};

/* - key database */
struct tcp_md5sig_key {
	struct hlist_node	node;
	u8			keylen;
	u8			family; /* AF_INET or AF_INET6 */
	union tcp_md5_addr	addr;
	u8			prefixlen;
	u8			key[TCP_MD5SIG_MAXKEYLEN];
	struct rcu_head		rcu;
};

extern const struct tcp_sock_af_ops tcp_sock_ipv4_specific;
extern const struct tcp_sock_af_ops tcp_sock_ipv6_specific;
extern const struct tcp_sock_af_ops tcp_sock_ipv6_mapped_specific;

/* - functions */
int tcp_v4_md5_hash_skb(char *md5_hash, const struct tcp_md5sig_key *key,
			const struct sock *sk, const struct sk_buff *skb);

struct tcp_md5sig_key *tcp_v4_md5_lookup(const struct sock *sk,
					 const struct sock *addr_sk);

bool tcp_v4_inbound_md5_hash(const struct sock *sk,
			     const struct sk_buff *skb);

struct tcp_md5sig_key *tcp_v6_md5_lookup(const struct sock *sk,
					 const struct sock *addr_sk);

int tcp_v6_md5_hash_skb(char *md5_hash,
			const struct tcp_md5sig_key *key,
			const struct sock *sk,
			const struct sk_buff *skb);

bool tcp_v6_inbound_md5_hash(const struct sock *sk,
			     const struct sk_buff *skb);

int tcp_md5_diag_get_aux(struct sock *sk, bool net_admin, struct sk_buff *skb);

int tcp_md5_diag_get_aux_size(struct sock *sk, bool net_admin);

#else

static inline bool tcp_v4_inbound_md5_hash(const struct sock *sk,
					   const struct sk_buff *skb)
{
	return false;
}

static inline bool tcp_v6_inbound_md5_hash(const struct sock *sk,
					   const struct sk_buff *skb)
{
	return false;
}

#endif

#endif /* _LINUX_TCP_MD5_H */
