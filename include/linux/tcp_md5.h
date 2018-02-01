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

/* - sock block */
struct tcp_md5sig_info {
	struct hlist_head	head;
	struct rcu_head		rcu;
};

union tcp_md5sum_block {
	struct tcp4_pseudohdr ip4;
#if IS_ENABLED(CONFIG_IPV6)
	struct tcp6_pseudohdr ip6;
#endif
};

/* - pool: digest algorithm, hash description and scratch buffer */
struct tcp_md5sig_pool {
	struct ahash_request	*md5_req;
	void			*scratch;
};

extern const struct tcp_sock_af_ops tcp_sock_ipv4_specific;
extern const struct tcp_sock_af_ops tcp_sock_ipv6_specific;
extern const struct tcp_sock_af_ops tcp_sock_ipv6_mapped_specific;

/* - functions */
int tcp_v4_md5_hash_skb(char *md5_hash, const struct tcp_md5sig_key *key,
			const struct sock *sk, const struct sk_buff *skb);

struct tcp_md5sig_key *tcp_v4_md5_lookup(const struct sock *sk,
					 const struct sock *addr_sk);

void tcp_v4_md5_destroy_sock(struct sock *sk);

int tcp_v4_md5_send_response_prepare(struct sk_buff *skb, u8 flags,
				     unsigned int remaining,
				     struct tcp_out_options *opts,
				     const struct sock *sk);

void tcp_v4_md5_send_response_write(__be32 *topt, struct sk_buff *skb,
				    struct tcphdr *t1,
				    struct tcp_out_options *opts,
				    const struct sock *sk);

int tcp_v6_md5_send_response_prepare(struct sk_buff *skb, u8 flags,
				     unsigned int remaining,
				     struct tcp_out_options *opts,
				     const struct sock *sk);

void tcp_v6_md5_send_response_write(__be32 *topt, struct sk_buff *skb,
				    struct tcphdr *t1,
				    struct tcp_out_options *opts,
				    const struct sock *sk);

bool tcp_v4_inbound_md5_hash(const struct sock *sk,
			     const struct sk_buff *skb);

void tcp_v4_md5_syn_recv_sock(const struct sock *listener, struct sock *sk);

void tcp_v6_md5_syn_recv_sock(const struct sock *listener, struct sock *sk);

void tcp_md5_time_wait(struct sock *sk, struct inet_timewait_sock *tw);

struct tcp_md5sig_key *tcp_v6_md5_lookup(const struct sock *sk,
					 const struct sock *addr_sk);

int tcp_v6_md5_hash_skb(char *md5_hash,
			const struct tcp_md5sig_key *key,
			const struct sock *sk,
			const struct sk_buff *skb);

bool tcp_v6_inbound_md5_hash(const struct sock *sk,
			     const struct sk_buff *skb);

static inline void tcp_md5_twsk_destructor(struct tcp_timewait_sock *twsk)
{
	if (twsk->tw_md5_key)
		kfree_rcu(twsk->tw_md5_key, rcu);
}

static inline void tcp_md5_add_header_len(const struct sock *listener,
					  struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (tp->af_specific->md5_lookup(listener, sk))
		tp->tcp_header_len += TCPOLEN_MD5SIG_ALIGNED;
}

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
