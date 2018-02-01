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

/* - functions */

int tcp_md5_parse_keys(struct sock *sk, int optname, char __user *optval,
		       int optlen);

int tcp_md5_diag_get_aux(struct sock *sk, bool net_admin, struct sk_buff *skb);

int tcp_md5_diag_get_aux_size(struct sock *sk, bool net_admin);

#endif /* CONFIG_TCP_MD5SIG */
#endif /* _LINUX_TCP_MD5_H */
