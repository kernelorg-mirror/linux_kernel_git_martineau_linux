/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/inet_diag.h>
#include <linux/inetdevice.h>
#include <linux/tcp.h>
#include <linux/tcp_md5.h>

#include <crypto/hash.h>

#include <net/inet6_hashtables.h>

static DEFINE_PER_CPU(struct tcp_md5sig_pool, tcp_md5sig_pool);
static DEFINE_MUTEX(tcp_md5sig_mutex);
static bool tcp_md5sig_pool_populated;

#define tcp_twsk_md5_key(twsk)	((twsk)->tw_md5_key)

static void __tcp_alloc_md5sig_pool(void)
{
	struct crypto_ahash *hash;
	int cpu;

	hash = crypto_alloc_ahash("md5", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(hash))
		return;

	for_each_possible_cpu(cpu) {
		void *scratch = per_cpu(tcp_md5sig_pool, cpu).scratch;
		struct ahash_request *req;

		if (!scratch) {
			scratch = kmalloc_node(sizeof(union tcp_md5sum_block) +
					       sizeof(struct tcphdr),
					       GFP_KERNEL,
					       cpu_to_node(cpu));
			if (!scratch)
				return;
			per_cpu(tcp_md5sig_pool, cpu).scratch = scratch;
		}
		if (per_cpu(tcp_md5sig_pool, cpu).md5_req)
			continue;

		req = ahash_request_alloc(hash, GFP_KERNEL);
		if (!req)
			return;

		ahash_request_set_callback(req, 0, NULL, NULL);

		per_cpu(tcp_md5sig_pool, cpu).md5_req = req;
	}
	/* before setting tcp_md5sig_pool_populated, we must commit all writes
	 * to memory. See smp_rmb() in tcp_get_md5sig_pool()
	 */
	smp_wmb();
	tcp_md5sig_pool_populated = true;
}

static bool tcp_alloc_md5sig_pool(void)
{
	if (unlikely(!tcp_md5sig_pool_populated)) {
		mutex_lock(&tcp_md5sig_mutex);

		if (!tcp_md5sig_pool_populated)
			__tcp_alloc_md5sig_pool();

		mutex_unlock(&tcp_md5sig_mutex);
	}
	return tcp_md5sig_pool_populated;
}

static void tcp_put_md5sig_pool(void)
{
	local_bh_enable();
}

/**
 *	tcp_get_md5sig_pool - get md5sig_pool for this user
 *
 *	We use percpu structure, so if we succeed, we exit with preemption
 *	and BH disabled, to make sure another thread or softirq handling
 *	wont try to get same context.
 */
static struct tcp_md5sig_pool *tcp_get_md5sig_pool(void)
{
	local_bh_disable();

	if (tcp_md5sig_pool_populated) {
		/* coupled with smp_wmb() in __tcp_alloc_md5sig_pool() */
		smp_rmb();
		return this_cpu_ptr(&tcp_md5sig_pool);
	}
	local_bh_enable();
	return NULL;
}

static struct tcp_md5sig_key *tcp_md5_do_lookup_exact(const struct sock *sk,
						      const union tcp_md5_addr *addr,
						      int family, u8 prefixlen)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_md5sig_key *key;
	unsigned int size = sizeof(struct in_addr);
	const struct tcp_md5sig_info *md5sig;

	/* caller either holds rcu_read_lock() or socket lock */
	md5sig = rcu_dereference_check(tp->md5sig_info,
				       lockdep_sock_is_held(sk));
	if (!md5sig)
		return NULL;
#if IS_ENABLED(CONFIG_IPV6)
	if (family == AF_INET6)
		size = sizeof(struct in6_addr);
#endif
	hlist_for_each_entry_rcu(key, &md5sig->head, node) {
		if (key->family != family)
			continue;
		if (!memcmp(&key->addr, addr, size) &&
		    key->prefixlen == prefixlen)
			return key;
	}
	return NULL;
}

/* This can be called on a newly created socket, from other files */
static int tcp_md5_do_add(struct sock *sk, const union tcp_md5_addr *addr,
			  int family, u8 prefixlen, const u8 *newkey,
			  u8 newkeylen, gfp_t gfp)
{
	/* Add Key to the list */
	struct tcp_md5sig_key *key;
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_md5sig_info *md5sig;

	key = tcp_md5_do_lookup_exact(sk, addr, family, prefixlen);
	if (key) {
		/* Pre-existing entry - just update that one. */
		memcpy(key->key, newkey, newkeylen);
		key->keylen = newkeylen;
		return 0;
	}

	md5sig = rcu_dereference_protected(tp->md5sig_info,
					   lockdep_sock_is_held(sk));
	if (!md5sig) {
		md5sig = kmalloc(sizeof(*md5sig), gfp);
		if (!md5sig)
			return -ENOMEM;

		sk_nocaps_add(sk, NETIF_F_GSO_MASK);
		INIT_HLIST_HEAD(&md5sig->head);
		rcu_assign_pointer(tp->md5sig_info, md5sig);
	}

	key = sock_kmalloc(sk, sizeof(*key), gfp);
	if (!key)
		return -ENOMEM;
	if (!tcp_alloc_md5sig_pool()) {
		sock_kfree_s(sk, key, sizeof(*key));
		return -ENOMEM;
	}

	memcpy(key->key, newkey, newkeylen);
	key->keylen = newkeylen;
	key->family = family;
	key->prefixlen = prefixlen;
	memcpy(&key->addr, addr,
	       (family == AF_INET6) ? sizeof(struct in6_addr) :
				      sizeof(struct in_addr));
	hlist_add_head_rcu(&key->node, &md5sig->head);
	return 0;
}

static void tcp_clear_md5_list(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_md5sig_key *key;
	struct hlist_node *n;
	struct tcp_md5sig_info *md5sig;

	md5sig = rcu_dereference_protected(tp->md5sig_info, 1);

	hlist_for_each_entry_safe(key, n, &md5sig->head, node) {
		hlist_del_rcu(&key->node);
		atomic_sub(sizeof(*key), &sk->sk_omem_alloc);
		kfree_rcu(key, rcu);
	}
}

static int tcp_md5_do_del(struct sock *sk, const union tcp_md5_addr *addr,
			  int family, u8 prefixlen)
{
	struct tcp_md5sig_key *key;

	key = tcp_md5_do_lookup_exact(sk, addr, family, prefixlen);
	if (!key)
		return -ENOENT;
	hlist_del_rcu(&key->node);
	atomic_sub(sizeof(*key), &sk->sk_omem_alloc);
	kfree_rcu(key, rcu);
	return 0;
}

static int tcp_md5_hash_key(struct tcp_md5sig_pool *hp,
			    const struct tcp_md5sig_key *key)
{
	struct scatterlist sg;

	sg_init_one(&sg, key->key, key->keylen);
	ahash_request_set_crypt(hp->md5_req, &sg, NULL, key->keylen);
	return crypto_ahash_update(hp->md5_req);
}

static int tcp_v4_parse_md5_keys(struct sock *sk, int optname,
				 char __user *optval, int optlen)
{
	struct tcp_md5sig cmd;
	struct sockaddr_in *sin = (struct sockaddr_in *)&cmd.tcpm_addr;
	u8 prefixlen = 32;

	if (optlen < sizeof(cmd))
		return -EINVAL;

	if (copy_from_user(&cmd, optval, sizeof(cmd)))
		return -EFAULT;

	if (sin->sin_family != AF_INET)
		return -EINVAL;

	if (optname == TCP_MD5SIG_EXT &&
	    cmd.tcpm_flags & TCP_MD5SIG_FLAG_PREFIX) {
		prefixlen = cmd.tcpm_prefixlen;
		if (prefixlen > 32)
			return -EINVAL;
	}

	if (!cmd.tcpm_keylen)
		return tcp_md5_do_del(sk, (union tcp_md5_addr *)&sin->sin_addr.s_addr,
				      AF_INET, prefixlen);

	if (cmd.tcpm_keylen > TCP_MD5SIG_MAXKEYLEN)
		return -EINVAL;

	return tcp_md5_do_add(sk, (union tcp_md5_addr *)&sin->sin_addr.s_addr,
			      AF_INET, prefixlen, cmd.tcpm_key, cmd.tcpm_keylen,
			      GFP_KERNEL);
}

#if IS_ENABLED(CONFIG_IPV6)
static int tcp_v6_parse_md5_keys(struct sock *sk, int optname,
				 char __user *optval, int optlen)
{
	struct tcp_md5sig cmd;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&cmd.tcpm_addr;
	u8 prefixlen;

	if (optlen < sizeof(cmd))
		return -EINVAL;

	if (copy_from_user(&cmd, optval, sizeof(cmd)))
		return -EFAULT;

	if (sin6->sin6_family != AF_INET6)
		return -EINVAL;

	if (optname == TCP_MD5SIG_EXT &&
	    cmd.tcpm_flags & TCP_MD5SIG_FLAG_PREFIX) {
		prefixlen = cmd.tcpm_prefixlen;
		if (prefixlen > 128 || (ipv6_addr_v4mapped(&sin6->sin6_addr) &&
					prefixlen > 32))
			return -EINVAL;
	} else {
		prefixlen = ipv6_addr_v4mapped(&sin6->sin6_addr) ? 32 : 128;
	}

	if (!cmd.tcpm_keylen) {
		if (ipv6_addr_v4mapped(&sin6->sin6_addr))
			return tcp_md5_do_del(sk, (union tcp_md5_addr *)&sin6->sin6_addr.s6_addr32[3],
					      AF_INET, prefixlen);
		return tcp_md5_do_del(sk, (union tcp_md5_addr *)&sin6->sin6_addr,
				      AF_INET6, prefixlen);
	}

	if (cmd.tcpm_keylen > TCP_MD5SIG_MAXKEYLEN)
		return -EINVAL;

	if (ipv6_addr_v4mapped(&sin6->sin6_addr))
		return tcp_md5_do_add(sk, (union tcp_md5_addr *)&sin6->sin6_addr.s6_addr32[3],
				      AF_INET, prefixlen, cmd.tcpm_key,
				      cmd.tcpm_keylen, GFP_KERNEL);

	return tcp_md5_do_add(sk, (union tcp_md5_addr *)&sin6->sin6_addr,
			      AF_INET6, prefixlen, cmd.tcpm_key,
			      cmd.tcpm_keylen, GFP_KERNEL);
}
#endif

static int tcp_v4_md5_hash_headers(struct tcp_md5sig_pool *hp,
				   __be32 daddr, __be32 saddr,
				   const struct tcphdr *th, int nbytes)
{
	struct tcp4_pseudohdr *bp;
	struct scatterlist sg;
	struct tcphdr *_th;

	bp = hp->scratch;
	bp->saddr = saddr;
	bp->daddr = daddr;
	bp->pad = 0;
	bp->protocol = IPPROTO_TCP;
	bp->len = cpu_to_be16(nbytes);

	_th = (struct tcphdr *)(bp + 1);
	memcpy(_th, th, sizeof(*th));
	_th->check = 0;

	sg_init_one(&sg, bp, sizeof(*bp) + sizeof(*th));
	ahash_request_set_crypt(hp->md5_req, &sg, NULL,
				sizeof(*bp) + sizeof(*th));
	return crypto_ahash_update(hp->md5_req);
}

#if IS_ENABLED(CONFIG_IPV6)
static int tcp_v6_md5_hash_headers(struct tcp_md5sig_pool *hp,
				   const struct in6_addr *daddr,
				   const struct in6_addr *saddr,
				   const struct tcphdr *th, int nbytes)
{
	struct tcp6_pseudohdr *bp;
	struct scatterlist sg;
	struct tcphdr *_th;

	bp = hp->scratch;
	/* 1. TCP pseudo-header (RFC2460) */
	bp->saddr = *saddr;
	bp->daddr = *daddr;
	bp->protocol = cpu_to_be32(IPPROTO_TCP);
	bp->len = cpu_to_be32(nbytes);

	_th = (struct tcphdr *)(bp + 1);
	memcpy(_th, th, sizeof(*th));
	_th->check = 0;

	sg_init_one(&sg, bp, sizeof(*bp) + sizeof(*th));
	ahash_request_set_crypt(hp->md5_req, &sg, NULL,
				sizeof(*bp) + sizeof(*th));
	return crypto_ahash_update(hp->md5_req);
}
#endif

static int tcp_v4_md5_hash_hdr(char *md5_hash, const struct tcp_md5sig_key *key,
			       __be32 daddr, __be32 saddr,
			       const struct tcphdr *th)
{
	struct tcp_md5sig_pool *hp;
	struct ahash_request *req;

	hp = tcp_get_md5sig_pool();
	if (!hp)
		goto clear_hash_noput;
	req = hp->md5_req;

	if (crypto_ahash_init(req))
		goto clear_hash;
	if (tcp_v4_md5_hash_headers(hp, daddr, saddr, th, th->doff << 2))
		goto clear_hash;
	if (tcp_md5_hash_key(hp, key))
		goto clear_hash;
	ahash_request_set_crypt(req, NULL, md5_hash, 0);
	if (crypto_ahash_final(req))
		goto clear_hash;

	tcp_put_md5sig_pool();
	return 0;

clear_hash:
	tcp_put_md5sig_pool();
clear_hash_noput:
	memset(md5_hash, 0, 16);
	return 1;
}

#if IS_ENABLED(CONFIG_IPV6)
static int tcp_v6_md5_hash_hdr(char *md5_hash, const struct tcp_md5sig_key *key,
			       const struct in6_addr *daddr,
			       struct in6_addr *saddr, const struct tcphdr *th)
{
	struct tcp_md5sig_pool *hp;
	struct ahash_request *req;

	hp = tcp_get_md5sig_pool();
	if (!hp)
		goto clear_hash_noput;
	req = hp->md5_req;

	if (crypto_ahash_init(req))
		goto clear_hash;
	if (tcp_v6_md5_hash_headers(hp, daddr, saddr, th, th->doff << 2))
		goto clear_hash;
	if (tcp_md5_hash_key(hp, key))
		goto clear_hash;
	ahash_request_set_crypt(req, NULL, md5_hash, 0);
	if (crypto_ahash_final(req))
		goto clear_hash;

	tcp_put_md5sig_pool();
	return 0;

clear_hash:
	tcp_put_md5sig_pool();
clear_hash_noput:
	memset(md5_hash, 0, 16);
	return 1;
}
#endif

/* RFC2385 MD5 checksumming requires a mapping of
 * IP address->MD5 Key.
 * We need to maintain these in the sk structure.
 */

/* Find the Key structure for an address.  */
static struct tcp_md5sig_key *tcp_md5_do_lookup(const struct sock *sk,
						const union tcp_md5_addr *addr,
						int family)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_md5sig_key *key;
	const struct tcp_md5sig_info *md5sig;
	__be32 mask;
	struct tcp_md5sig_key *best_match = NULL;
	bool match;

	/* caller either holds rcu_read_lock() or socket lock */
	md5sig = rcu_dereference_check(tp->md5sig_info,
				       lockdep_sock_is_held(sk));
	if (!md5sig)
		return NULL;

	hlist_for_each_entry_rcu(key, &md5sig->head, node) {
		if (key->family != family)
			continue;

		if (family == AF_INET) {
			mask = inet_make_mask(key->prefixlen);
			match = (key->addr.a4.s_addr & mask) ==
				(addr->a4.s_addr & mask);
#if IS_ENABLED(CONFIG_IPV6)
		} else if (family == AF_INET6) {
			match = ipv6_prefix_equal(&key->addr.a6, &addr->a6,
						  key->prefixlen);
#endif
		} else {
			match = false;
		}

		if (match && (!best_match ||
			      key->prefixlen > best_match->prefixlen))
			best_match = key;
	}
	return best_match;
}

/* Parse MD5 Signature option */
static const u8 *tcp_parse_md5sig_option(const struct tcphdr *th)
{
	int length = (th->doff << 2) - sizeof(*th);
	const u8 *ptr = (const u8 *)(th + 1);

	/* If the TCP option is too short, we can short cut */
	if (length < TCPOLEN_MD5SIG)
		return NULL;

	while (length > 0) {
		int opcode = *ptr++;
		int opsize;

		switch (opcode) {
		case TCPOPT_EOL:
			return NULL;
		case TCPOPT_NOP:
			length--;
			continue;
		default:
			opsize = *ptr++;
			if (opsize < 2 || opsize > length)
				return NULL;
			if (opcode == TCPOPT_MD5SIG)
				return opsize == TCPOLEN_MD5SIG ? ptr : NULL;
		}
		ptr += opsize - 2;
		length -= opsize;
	}
	return NULL;
}

#if IS_ENABLED(CONFIG_IPV6)
static struct tcp_md5sig_key *tcp_v6_md5_do_lookup(const struct sock *sk,
						   const struct in6_addr *addr)
{
	return tcp_md5_do_lookup(sk, (union tcp_md5_addr *)addr, AF_INET6);
}
#endif

static int tcp_md5_hash_skb_data(struct tcp_md5sig_pool *hp,
				 const struct sk_buff *skb,
				 unsigned int header_len)
{
	struct scatterlist sg;
	const struct tcphdr *tp = tcp_hdr(skb);
	struct ahash_request *req = hp->md5_req;
	unsigned int i;
	const unsigned int head_data_len = skb_headlen(skb) > header_len ?
					   skb_headlen(skb) - header_len : 0;
	const struct skb_shared_info *shi = skb_shinfo(skb);
	struct sk_buff *frag_iter;

	sg_init_table(&sg, 1);

	sg_set_buf(&sg, ((u8 *)tp) + header_len, head_data_len);
	ahash_request_set_crypt(req, &sg, NULL, head_data_len);
	if (crypto_ahash_update(req))
		return 1;

	for (i = 0; i < shi->nr_frags; ++i) {
		const struct skb_frag_struct *f = &shi->frags[i];
		unsigned int offset = f->page_offset;
		struct page *page = skb_frag_page(f) + (offset >> PAGE_SHIFT);

		sg_set_page(&sg, page, skb_frag_size(f),
			    offset_in_page(offset));
		ahash_request_set_crypt(req, &sg, NULL, skb_frag_size(f));
		if (crypto_ahash_update(req))
			return 1;
	}

	skb_walk_frags(skb, frag_iter)
		if (tcp_md5_hash_skb_data(hp, frag_iter, 0))
			return 1;

	return 0;
}

int tcp_v4_md5_send_response_prepare(struct sk_buff *skb, u8 flags,
				     unsigned int remaining,
				     struct tcp_out_options *opts,
				     const struct sock *sk)
{
	const struct tcphdr *th = tcp_hdr(skb);
	const struct iphdr *iph = ip_hdr(skb);
	const __u8 *hash_location = NULL;

	rcu_read_lock();
	hash_location = tcp_parse_md5sig_option(th);
	if (sk && sk_fullsock(sk)) {
		opts->md5 = tcp_md5_do_lookup(sk,
					      (union tcp_md5_addr *)&iph->saddr,
					      AF_INET);
	} else if (sk && sk->sk_state == TCP_TIME_WAIT) {
		struct tcp_timewait_sock *tcptw = tcp_twsk(sk);

		opts->md5 = tcp_twsk_md5_key(tcptw);
	} else if (sk && sk->sk_state == TCP_NEW_SYN_RECV) {
		opts->md5 = tcp_md5_do_lookup(sk,
					      (union tcp_md5_addr *)&iph->saddr,
					      AF_INET);
	} else if (hash_location) {
		unsigned char newhash[16];
		struct sock *sk1;
		int genhash;

		/* active side is lost. Try to find listening socket through
		 * source port, and then find md5 key through listening socket.
		 * we are not loose security here:
		 * Incoming packet is checked with md5 hash with finding key,
		 * no RST generated if md5 hash doesn't match.
		 */
		sk1 = __inet_lookup_listener(dev_net(skb_dst(skb)->dev),
					     &tcp_hashinfo, NULL, 0,
					     iph->saddr,
					     th->source, iph->daddr,
					     ntohs(th->source), inet_iif(skb),
					     tcp_v4_sdif(skb));
		/* don't send rst if it can't find key */
		if (!sk1)
			goto out_err;

		opts->md5 = tcp_md5_do_lookup(sk1, (union tcp_md5_addr *)
					      &iph->saddr, AF_INET);
		if (!opts->md5)
			goto out_err;

		genhash = tcp_v4_md5_hash_skb(newhash, opts->md5, NULL, skb);
		if (genhash || memcmp(hash_location, newhash, 16) != 0)
			goto out_err;
	}

	if (opts->md5)
		return TCPOLEN_MD5SIG_ALIGNED;

	rcu_read_unlock();
	return 0;

out_err:
	rcu_read_unlock();
	return -1;
}

void tcp_v4_md5_send_response_write(__be32 *topt, struct sk_buff *skb,
				    struct tcphdr *t1,
				    struct tcp_out_options *opts,
				    const struct sock *sk)
{
	if (opts->md5) {
		*topt++ = htonl((TCPOPT_NOP << 24) |
				(TCPOPT_NOP << 16) |
				(TCPOPT_MD5SIG << 8) |
				TCPOLEN_MD5SIG);

		tcp_v4_md5_hash_hdr((__u8 *)topt, opts->md5,
				    ip_hdr(skb)->saddr,
				    ip_hdr(skb)->daddr, t1);
		rcu_read_unlock();
	}
}

#if IS_ENABLED(CONFIG_IPV6)
int tcp_v6_md5_send_response_prepare(struct sk_buff *skb, u8 flags,
				     unsigned int remaining,
				     struct tcp_out_options *opts,
				     const struct sock *sk)
{
	const struct tcphdr *th = tcp_hdr(skb);
	struct ipv6hdr *ipv6h = ipv6_hdr(skb);
	const __u8 *hash_location = NULL;

	rcu_read_lock();
	hash_location = tcp_parse_md5sig_option(th);
	if (sk && sk_fullsock(sk)) {
		opts->md5 = tcp_v6_md5_do_lookup(sk, &ipv6h->saddr);
	} else if (sk && sk->sk_state == TCP_TIME_WAIT) {
		struct tcp_timewait_sock *tcptw = tcp_twsk(sk);

		opts->md5 = tcp_twsk_md5_key(tcptw);
	} else if (sk && sk->sk_state == TCP_NEW_SYN_RECV) {
		opts->md5 = tcp_v6_md5_do_lookup(sk, &ipv6h->saddr);
	} else if (hash_location) {
		unsigned char newhash[16];
		struct sock *sk1;
		int genhash;

		/* active side is lost. Try to find listening socket through
		 * source port, and then find md5 key through listening socket.
		 * we are not loose security here:
		 * Incoming packet is checked with md5 hash with finding key,
		 * no RST generated if md5 hash doesn't match.
		 */
		sk1 = inet6_lookup_listener(dev_net(skb_dst(skb)->dev),
					    &tcp_hashinfo, NULL, 0,
					    &ipv6h->saddr,
					    th->source, &ipv6h->daddr,
					    ntohs(th->source), tcp_v6_iif(skb),
					    tcp_v6_sdif(skb));
		if (!sk1)
			goto out_err;

		opts->md5 = tcp_v6_md5_do_lookup(sk1, &ipv6h->saddr);
		if (!opts->md5)
			goto out_err;

		genhash = tcp_v6_md5_hash_skb(newhash, opts->md5, NULL, skb);
		if (genhash || memcmp(hash_location, newhash, 16) != 0)
			goto out_err;
	}

	if (opts->md5)
		return TCPOLEN_MD5SIG_ALIGNED;

	rcu_read_unlock();
	return 0;

out_err:
	rcu_read_unlock();
	return -1;
}
EXPORT_SYMBOL_GPL(tcp_v6_md5_send_response_prepare);

void tcp_v6_md5_send_response_write(__be32 *topt, struct sk_buff *skb,
				    struct tcphdr *t1,
				    struct tcp_out_options *opts,
				    const struct sock *sk)
{
	if (opts->md5) {
		*topt++ = htonl((TCPOPT_NOP << 24) | (TCPOPT_NOP << 16) |
				(TCPOPT_MD5SIG << 8) | TCPOLEN_MD5SIG);
		tcp_v6_md5_hash_hdr((__u8 *)topt, opts->md5,
				    &ipv6_hdr(skb)->saddr,
				    &ipv6_hdr(skb)->daddr, t1);

		rcu_read_unlock();
	}
}
EXPORT_SYMBOL_GPL(tcp_v6_md5_send_response_write);
#endif

struct tcp_md5sig_key *tcp_v4_md5_lookup(const struct sock *sk,
					 const struct sock *addr_sk)
{
	const union tcp_md5_addr *addr;

	addr = (const union tcp_md5_addr *)&addr_sk->sk_daddr;
	return tcp_md5_do_lookup(sk, addr, AF_INET);
}
EXPORT_SYMBOL(tcp_v4_md5_lookup);

int tcp_v4_md5_hash_skb(char *md5_hash, const struct tcp_md5sig_key *key,
			const struct sock *sk,
			const struct sk_buff *skb)
{
	struct tcp_md5sig_pool *hp;
	struct ahash_request *req;
	const struct tcphdr *th = tcp_hdr(skb);
	__be32 saddr, daddr;

	if (sk) { /* valid for establish/request sockets */
		saddr = sk->sk_rcv_saddr;
		daddr = sk->sk_daddr;
	} else {
		const struct iphdr *iph = ip_hdr(skb);

		saddr = iph->saddr;
		daddr = iph->daddr;
	}

	hp = tcp_get_md5sig_pool();
	if (!hp)
		goto clear_hash_noput;
	req = hp->md5_req;

	if (crypto_ahash_init(req))
		goto clear_hash;

	if (tcp_v4_md5_hash_headers(hp, daddr, saddr, th, skb->len))
		goto clear_hash;
	if (tcp_md5_hash_skb_data(hp, skb, th->doff << 2))
		goto clear_hash;
	if (tcp_md5_hash_key(hp, key))
		goto clear_hash;
	ahash_request_set_crypt(req, NULL, md5_hash, 0);
	if (crypto_ahash_final(req))
		goto clear_hash;

	tcp_put_md5sig_pool();
	return 0;

clear_hash:
	tcp_put_md5sig_pool();
clear_hash_noput:
	memset(md5_hash, 0, 16);
	return 1;
}
EXPORT_SYMBOL(tcp_v4_md5_hash_skb);

#if IS_ENABLED(CONFIG_IPV6)
int tcp_v6_md5_hash_skb(char *md5_hash,
			const struct tcp_md5sig_key *key,
			const struct sock *sk,
			const struct sk_buff *skb)
{
	const struct in6_addr *saddr, *daddr;
	struct tcp_md5sig_pool *hp;
	struct ahash_request *req;
	const struct tcphdr *th = tcp_hdr(skb);

	if (sk) { /* valid for establish/request sockets */
		saddr = &sk->sk_v6_rcv_saddr;
		daddr = &sk->sk_v6_daddr;
	} else {
		const struct ipv6hdr *ip6h = ipv6_hdr(skb);

		saddr = &ip6h->saddr;
		daddr = &ip6h->daddr;
	}

	hp = tcp_get_md5sig_pool();
	if (!hp)
		goto clear_hash_noput;
	req = hp->md5_req;

	if (crypto_ahash_init(req))
		goto clear_hash;

	if (tcp_v6_md5_hash_headers(hp, daddr, saddr, th, skb->len))
		goto clear_hash;
	if (tcp_md5_hash_skb_data(hp, skb, th->doff << 2))
		goto clear_hash;
	if (tcp_md5_hash_key(hp, key))
		goto clear_hash;
	ahash_request_set_crypt(req, NULL, md5_hash, 0);
	if (crypto_ahash_final(req))
		goto clear_hash;

	tcp_put_md5sig_pool();
	return 0;

clear_hash:
	tcp_put_md5sig_pool();
clear_hash_noput:
	memset(md5_hash, 0, 16);
	return 1;
}
EXPORT_SYMBOL_GPL(tcp_v6_md5_hash_skb);
#endif

/* Called with rcu_read_lock() */
bool tcp_v4_inbound_md5_hash(const struct sock *sk,
			     const struct sk_buff *skb)
{
	/* This gets called for each TCP segment that arrives
	 * so we want to be efficient.
	 * We have 3 drop cases:
	 * o No MD5 hash and one expected.
	 * o MD5 hash and we're not expecting one.
	 * o MD5 hash and its wrong.
	 */
	const __u8 *hash_location = NULL;
	struct tcp_md5sig_key *hash_expected;
	const struct iphdr *iph = ip_hdr(skb);
	const struct tcphdr *th = tcp_hdr(skb);
	int genhash;
	unsigned char newhash[16];

	hash_expected = tcp_md5_do_lookup(sk, (union tcp_md5_addr *)&iph->saddr,
					  AF_INET);
	hash_location = tcp_parse_md5sig_option(th);

	/* We've parsed the options - do we have a hash? */
	if (!hash_expected && !hash_location)
		return false;

	if (hash_expected && !hash_location) {
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPMD5NOTFOUND);
		return true;
	}

	if (!hash_expected && hash_location) {
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPMD5UNEXPECTED);
		return true;
	}

	/* Okay, so this is hash_expected and hash_location -
	 * so we need to calculate the checksum.
	 */
	genhash = tcp_v4_md5_hash_skb(newhash,
				      hash_expected,
				      NULL, skb);

	if (genhash || memcmp(hash_location, newhash, 16) != 0) {
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPMD5FAILURE);
		net_info_ratelimited("MD5 Hash failed for (%pI4, %d)->(%pI4, %d)%s\n",
				     &iph->saddr, ntohs(th->source),
				     &iph->daddr, ntohs(th->dest),
				     genhash ? " tcp_v4_calc_md5_hash failed"
				     : "");
		return true;
	}
	return false;
}

#if IS_ENABLED(CONFIG_IPV6)
bool tcp_v6_inbound_md5_hash(const struct sock *sk,
			     const struct sk_buff *skb)
{
	const __u8 *hash_location = NULL;
	struct tcp_md5sig_key *hash_expected;
	const struct ipv6hdr *ip6h = ipv6_hdr(skb);
	const struct tcphdr *th = tcp_hdr(skb);
	int genhash;
	u8 newhash[16];

	hash_expected = tcp_v6_md5_do_lookup(sk, &ip6h->saddr);
	hash_location = tcp_parse_md5sig_option(th);

	/* We've parsed the options - do we have a hash? */
	if (!hash_expected && !hash_location)
		return false;

	if (hash_expected && !hash_location) {
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPMD5NOTFOUND);
		return true;
	}

	if (!hash_expected && hash_location) {
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPMD5UNEXPECTED);
		return true;
	}

	/* check the signature */
	genhash = tcp_v6_md5_hash_skb(newhash,
				      hash_expected,
				      NULL, skb);

	if (genhash || memcmp(hash_location, newhash, 16) != 0) {
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPMD5FAILURE);
		net_info_ratelimited("MD5 Hash %s for [%pI6c]:%u->[%pI6c]:%u\n",
				     genhash ? "failed" : "mismatch",
				     &ip6h->saddr, ntohs(th->source),
				     &ip6h->daddr, ntohs(th->dest));
		return true;
	}

	return false;
}
EXPORT_SYMBOL_GPL(tcp_v6_inbound_md5_hash);
#endif

void tcp_v4_md5_destroy_sock(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/* Clean up the MD5 key list, if any */
	if (tp->md5sig_info) {
		tcp_clear_md5_list(sk);
		kfree_rcu(rcu_dereference_protected(tp->md5sig_info, 1), rcu);
		tp->md5sig_info = NULL;
	}
}

void tcp_v4_md5_syn_recv_sock(const struct sock *listener, struct sock *sk)
{
	struct inet_sock *inet = inet_sk(sk);
	struct tcp_md5sig_key *key;

	/* Copy over the MD5 key from the original socket */
	key = tcp_md5_do_lookup(listener, (union tcp_md5_addr *)&inet->inet_daddr,
				AF_INET);
	if (key) {
		/* We're using one, so create a matching key
		 * on the sk structure. If we fail to get
		 * memory, then we end up not copying the key
		 * across. Shucks.
		 */
		tcp_md5_do_add(sk, (union tcp_md5_addr *)&inet->inet_daddr,
			       AF_INET, 32, key->key, key->keylen, GFP_ATOMIC);
		sk_nocaps_add(sk, NETIF_F_GSO_MASK);
	}
}

#if IS_ENABLED(CONFIG_IPV6)
void tcp_v6_md5_syn_recv_sock(const struct sock *listener, struct sock *sk)
{
	struct tcp_md5sig_key *key;

	/* Copy over the MD5 key from the original socket */
	key = tcp_v6_md5_do_lookup(listener, &sk->sk_v6_daddr);
	if (key) {
		/* We're using one, so create a matching key
		 * on the newsk structure. If we fail to get
		 * memory, then we end up not copying the key
		 * across. Shucks.
		 */
		tcp_md5_do_add(sk, (union tcp_md5_addr *)&sk->sk_v6_daddr,
			       AF_INET6, 128, key->key, key->keylen,
			       sk_gfp_mask(sk, GFP_ATOMIC));
	}
}
EXPORT_SYMBOL_GPL(tcp_v6_md5_syn_recv_sock);

struct tcp_md5sig_key *tcp_v6_md5_lookup(const struct sock *sk,
					 const struct sock *addr_sk)
{
	return tcp_v6_md5_do_lookup(sk, &addr_sk->sk_v6_daddr);
}
EXPORT_SYMBOL_GPL(tcp_v6_md5_lookup);
#endif

void tcp_md5_time_wait(struct sock *sk, struct inet_timewait_sock *tw)
{
	struct tcp_timewait_sock *tcptw = tcp_twsk((struct sock *)tw);
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_md5sig_key *key;

	/* The timewait bucket does not have the key DB from the
	 * sock structure. We just make a quick copy of the
	 * md5 key being used (if indeed we are using one)
	 * so the timewait ack generating code has the key.
	 */
	tcptw->tw_md5_key = NULL;
	key = tp->af_specific->md5_lookup(sk, sk);
	if (key) {
		tcptw->tw_md5_key = kmemdup(key, sizeof(*key), GFP_ATOMIC);
		BUG_ON(tcptw->tw_md5_key && !tcp_alloc_md5sig_pool());
	}
}

static void tcp_diag_md5sig_fill(struct tcp_diag_md5sig *info,
				 const struct tcp_md5sig_key *key)
{
	info->tcpm_family = key->family;
	info->tcpm_prefixlen = key->prefixlen;
	info->tcpm_keylen = key->keylen;
	memcpy(info->tcpm_key, key->key, key->keylen);

	if (key->family == AF_INET)
		info->tcpm_addr[0] = key->addr.a4.s_addr;
	#if IS_ENABLED(CONFIG_IPV6)
	else if (key->family == AF_INET6)
		memcpy(&info->tcpm_addr, &key->addr.a6,
		       sizeof(info->tcpm_addr));
	#endif
}

static int tcp_diag_put_md5sig(struct sk_buff *skb,
			       const struct tcp_md5sig_info *md5sig)
{
	const struct tcp_md5sig_key *key;
	struct tcp_diag_md5sig *info;
	struct nlattr *attr;
	int md5sig_count = 0;

	hlist_for_each_entry_rcu(key, &md5sig->head, node)
		md5sig_count++;
	if (md5sig_count == 0)
		return 0;

	attr = nla_reserve(skb, INET_DIAG_MD5SIG,
			   md5sig_count * sizeof(struct tcp_diag_md5sig));
	if (!attr)
		return -EMSGSIZE;

	info = nla_data(attr);
	memset(info, 0, md5sig_count * sizeof(struct tcp_diag_md5sig));
	hlist_for_each_entry_rcu(key, &md5sig->head, node) {
		tcp_diag_md5sig_fill(info++, key);
		if (--md5sig_count == 0)
			break;
	}

	return 0;
}

int tcp_md5_diag_get_aux(struct sock *sk, bool net_admin, struct sk_buff *skb)
{
	if (net_admin) {
		struct tcp_md5sig_info *md5sig;
		int err = 0;

		rcu_read_lock();
		md5sig = rcu_dereference(tcp_sk(sk)->md5sig_info);
		if (md5sig)
			err = tcp_diag_put_md5sig(skb, md5sig);
		rcu_read_unlock();
		if (err < 0)
			return err;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tcp_md5_diag_get_aux);

int tcp_md5_diag_get_aux_size(struct sock *sk, bool net_admin)
{
	int size = 0;

	if (net_admin && sk_fullsock(sk)) {
		const struct tcp_md5sig_info *md5sig;
		const struct tcp_md5sig_key *key;
		size_t md5sig_count = 0;

		rcu_read_lock();
		md5sig = rcu_dereference(tcp_sk(sk)->md5sig_info);
		if (md5sig) {
			hlist_for_each_entry_rcu(key, &md5sig->head, node)
				md5sig_count++;
		}
		rcu_read_unlock();
		size += nla_total_size(md5sig_count *
				       sizeof(struct tcp_diag_md5sig));
	}

	return size;
}
EXPORT_SYMBOL_GPL(tcp_md5_diag_get_aux_size);

const struct tcp_sock_af_ops tcp_sock_ipv4_specific = {
	.md5_lookup	= tcp_v4_md5_lookup,
	.calc_md5_hash	= tcp_v4_md5_hash_skb,
	.md5_parse	= tcp_v4_parse_md5_keys,
};

#if IS_ENABLED(CONFIG_IPV6)
const struct tcp_sock_af_ops tcp_sock_ipv6_specific = {
	.md5_lookup	=	tcp_v6_md5_lookup,
	.calc_md5_hash	=	tcp_v6_md5_hash_skb,
	.md5_parse	=	tcp_v6_parse_md5_keys,
};
EXPORT_SYMBOL_GPL(tcp_sock_ipv6_specific);

const struct tcp_sock_af_ops tcp_sock_ipv6_mapped_specific = {
	.md5_lookup	=	tcp_v4_md5_lookup,
	.calc_md5_hash	=	tcp_v4_md5_hash_skb,
	.md5_parse	=	tcp_v6_parse_md5_keys,
};
EXPORT_SYMBOL_GPL(tcp_sock_ipv6_mapped_specific);
#endif
