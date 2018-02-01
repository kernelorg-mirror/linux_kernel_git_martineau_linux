/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/inet_diag.h>
#include <linux/inetdevice.h>
#include <linux/tcp.h>
#include <linux/tcp_md5.h>

#include <crypto/hash.h>

#include <net/inet6_hashtables.h>

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

static DEFINE_PER_CPU(struct tcp_md5sig_pool, tcp_md5sig_pool);
static DEFINE_MUTEX(tcp_md5sig_mutex);
static bool tcp_md5sig_pool_populated;

static bool tcp_inbound_md5_hash(struct sock *sk, const struct sk_buff *skb,
				 struct tcp_options_received *opt_rx,
				 struct tcp_extopt_store *store);

static unsigned int tcp_md5_extopt_prepare(struct sk_buff *skb, u8 flags,
					   unsigned int remaining,
					   struct tcp_out_options *opts,
					   const struct sock *sk,
					   struct tcp_extopt_store *store);

static __be32 *tcp_md5_extopt_write(__be32 *ptr, struct sk_buff *skb,
				    struct tcp_out_options *opts,
				    struct sock *sk,
				    struct tcp_extopt_store *store);

static int tcp_md5_send_response_prepare(struct sk_buff *orig, u8 flags,
					 unsigned int remaining,
					 struct tcp_out_options *opts,
					 const struct sock *sk,
					 struct tcp_extopt_store *store);

static __be32 *tcp_md5_send_response_write(__be32 *ptr, struct sk_buff *orig,
					   struct tcphdr *th,
					   struct tcp_out_options *opts,
					   const struct sock *sk,
					   struct tcp_extopt_store *store);

static int tcp_md5_extopt_add_header_len(const struct sock *orig,
					 const struct sock *sk,
					 struct tcp_extopt_store *store);

static struct tcp_extopt_store *tcp_md5_extopt_copy(struct sock *listener,
						    struct request_sock *req,
						    struct tcp_options_received *opt,
						    struct tcp_extopt_store *store);

static struct tcp_extopt_store *tcp_md5_extopt_move(struct sock *from,
						    struct sock *to,
						    struct tcp_extopt_store *store);

static void tcp_md5_extopt_destroy(struct tcp_extopt_store *store);

struct tcp_md5_extopt {
	struct tcp_extopt_store		store;
	struct tcp_md5sig_info __rcu	*md5sig_info;
	struct sock			*sk;
	struct rcu_head			rcu;
};

static const struct tcp_extopt_ops tcp_md5_extra_ops = {
	.option_kind		= TCPOPT_MD5SIG,
	.check			= tcp_inbound_md5_hash,
	.prepare		= tcp_md5_extopt_prepare,
	.write			= tcp_md5_extopt_write,
	.response_prepare	= tcp_md5_send_response_prepare,
	.response_write		= tcp_md5_send_response_write,
	.add_header_len		= tcp_md5_extopt_add_header_len,
	.copy			= tcp_md5_extopt_copy,
	.move			= tcp_md5_extopt_move,
	.destroy		= tcp_md5_extopt_destroy,
	.owner			= THIS_MODULE,
};

static struct tcp_md5_extopt *tcp_extopt_to_md5(struct tcp_extopt_store *store)
{
	return container_of(store, struct tcp_md5_extopt, store);
}

static struct tcp_md5_extopt *tcp_md5_opt_find(const struct sock *sk)
{
	struct tcp_extopt_store *ext_opt;

	ext_opt = tcp_extopt_find_kind(TCPOPT_MD5SIG, sk);

	return tcp_extopt_to_md5(ext_opt);
}

static int tcp_md5_register(struct sock *sk,
			    struct tcp_md5_extopt *md5_opt)
{
	return tcp_register_extopt(&md5_opt->store, sk);
}

static struct tcp_md5_extopt *tcp_md5_alloc_store(struct sock *sk)
{
	struct tcp_md5_extopt *md5_opt;

	md5_opt = kzalloc(sizeof(*md5_opt), GFP_ATOMIC);
	if (!md5_opt)
		return NULL;

	md5_opt->store.ops = &tcp_md5_extra_ops;
	md5_opt->sk = sk;

	return md5_opt;
}

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

static struct tcp_md5sig_key *tcp_md5_do_lookup_exact(const struct tcp_md5_extopt *md5_opt,
						      const union tcp_md5_addr *addr,
						      int family, u8 prefixlen)
{
	struct tcp_md5sig_key *key;
	unsigned int size = sizeof(struct in_addr);
	const struct tcp_md5sig_info *md5sig;

	/* caller either holds rcu_read_lock() or socket lock */
	md5sig = rcu_dereference_check(md5_opt->md5sig_info,
				       sk_fullsock(md5_opt->sk) && lockdep_sock_is_held(md5_opt->sk));
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
	struct tcp_md5sig_info *md5sig;
	struct tcp_md5_extopt *md5_opt;
	struct tcp_md5sig_key *key;

	md5_opt = tcp_md5_opt_find(sk);
	if (!md5_opt) {
		int ret;

		md5_opt = tcp_md5_alloc_store(sk);
		if (!md5_opt)
			return -ENOMEM;

		ret = tcp_md5_register(sk, md5_opt);
		if (ret) {
			kfree(md5_opt);
			return ret;
		}
	}

	key = tcp_md5_do_lookup_exact(md5_opt, addr, family, prefixlen);
	if (key) {
		/* Pre-existing entry - just update that one. */
		memcpy(key->key, newkey, newkeylen);
		key->keylen = newkeylen;
		return 0;
	}

	md5sig = rcu_dereference_protected(md5_opt->md5sig_info,
					   sk_fullsock(sk) && lockdep_sock_is_held(sk));
	if (!md5sig) {
		md5sig = kmalloc(sizeof(*md5sig), gfp);
		if (!md5sig)
			return -ENOMEM;

		sk_nocaps_add(sk, NETIF_F_GSO_MASK);
		INIT_HLIST_HEAD(&md5sig->head);
		rcu_assign_pointer(md5_opt->md5sig_info, md5sig);
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

static void tcp_clear_md5_list(struct tcp_md5_extopt *md5_opt)
{
	struct tcp_md5sig_info *md5sig;
	struct tcp_md5sig_key *key;
	struct hlist_node *n;

	md5sig = rcu_dereference_protected(md5_opt->md5sig_info, 1);

	hlist_for_each_entry_safe(key, n, &md5sig->head, node) {
		hlist_del_rcu(&key->node);
		if (md5_opt->sk && sk_fullsock(md5_opt->sk))
			atomic_sub(sizeof(*key), &md5_opt->sk->sk_omem_alloc);
		kfree_rcu(key, rcu);
	}
}

static int tcp_md5_do_del(struct sock *sk, const union tcp_md5_addr *addr,
			  int family, u8 prefixlen)
{
	struct tcp_md5_extopt *md5_opt;
	struct tcp_md5sig_key *key;

	md5_opt = tcp_md5_opt_find(sk);
	if (!md5_opt)
		return -ENOENT;

	key = tcp_md5_do_lookup_exact(md5_opt, addr, family, prefixlen);
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

int tcp_md5_parse_keys(struct sock *sk, int optname, char __user *optval,
		       int optlen)
{
	u8 prefixlen = 32, maxprefixlen;
	union tcp_md5_addr *tcpmd5addr;
	struct tcp_md5sig cmd;
	unsigned short family;

	if (optlen < sizeof(cmd))
		return -EINVAL;

	if (copy_from_user(&cmd, optval, sizeof(cmd)))
		return -EFAULT;

	family = cmd.tcpm_addr.ss_family;

	if (family != AF_INET && family != AF_INET6)
		return -EINVAL;

	if (sk->sk_family != family)
		return -EINVAL;

	if (family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&cmd.tcpm_addr;

		if (!ipv6_addr_v4mapped(&sin6->sin6_addr)) {
			tcpmd5addr = (union tcp_md5_addr *)&sin6->sin6_addr;
			maxprefixlen = 128;
		} else {
			tcpmd5addr = (union tcp_md5_addr *)&sin6->sin6_addr.s6_addr32[3];
			family = AF_INET;
			maxprefixlen = 32;
		}
	} else {
		struct sockaddr_in *sin = (struct sockaddr_in *)&cmd.tcpm_addr;

		tcpmd5addr = (union tcp_md5_addr *)&sin->sin_addr;
		maxprefixlen = 32;
	}

	if (optname == TCP_MD5SIG_EXT &&
	    cmd.tcpm_flags & TCP_MD5SIG_FLAG_PREFIX) {
		prefixlen = cmd.tcpm_prefixlen;
		if (prefixlen > maxprefixlen)
			return -EINVAL;
	}

	if (!cmd.tcpm_keylen)
		return tcp_md5_do_del(sk, tcpmd5addr, family, prefixlen);

	if (cmd.tcpm_keylen > TCP_MD5SIG_MAXKEYLEN)
		return -EINVAL;

	return tcp_md5_do_add(sk, tcpmd5addr, family, prefixlen, cmd.tcpm_key,
			      cmd.tcpm_keylen, GFP_KERNEL);
}

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
	struct tcp_md5sig_key *best_match = NULL;
	const struct tcp_md5sig_info *md5sig;
	struct tcp_md5_extopt *md5_opt;
	struct tcp_md5sig_key *key;
	__be32 mask;
	bool match;

	md5_opt = tcp_md5_opt_find(sk);
	if (!md5_opt)
		return NULL;

	/* caller either holds rcu_read_lock() or socket lock */
	md5sig = rcu_dereference_check(md5_opt->md5sig_info,
				       sk_fullsock(sk) && lockdep_sock_is_held(sk));
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

static int tcp_v4_md5_hash_skb(char *md5_hash, const struct tcp_md5sig_key *key,
			       const struct sock *sk, const struct sk_buff *skb)
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

#if IS_ENABLED(CONFIG_IPV6)
static int tcp_v6_md5_hash_skb(char *md5_hash,
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
#endif

static int tcp_v4_md5_send_response_prepare(struct sk_buff *skb, u8 flags,
					    unsigned int remaining,
					    struct tcp_out_options *opts,
					    const struct sock *sk)
{
	const struct iphdr *iph = ip_hdr(skb);

	rcu_read_lock();
	opts->md5 = tcp_md5_do_lookup(sk,
				      (union tcp_md5_addr *)&iph->saddr,
				      AF_INET);

	if (opts->md5)
		/* rcu_read_unlock() is in _response_write */
		return TCPOLEN_MD5SIG_ALIGNED;

	rcu_read_unlock();
	return 0;
}

static __be32 *tcp_v4_md5_send_response_write(__be32 *topt, struct sk_buff *skb,
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

		topt += 4;

		/* Unlocking from _response_prepare */
		rcu_read_unlock();
	}

	return topt;
}

#if IS_ENABLED(CONFIG_IPV6)
static int tcp_v6_md5_send_response_prepare(struct sk_buff *skb, u8 flags,
					    unsigned int remaining,
					    struct tcp_out_options *opts,
					    const struct sock *sk)
{
	struct ipv6hdr *ipv6h = ipv6_hdr(skb);

	rcu_read_lock();
	opts->md5 = tcp_v6_md5_do_lookup(sk, &ipv6h->saddr);

	if (opts->md5)
		/* rcu_read_unlock() is in _response_write */
		return TCPOLEN_MD5SIG_ALIGNED;

	rcu_read_unlock();
	return 0;
}

static __be32 *tcp_v6_md5_send_response_write(__be32 *topt, struct sk_buff *skb,
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

		topt += 4;

		/* Unlocking from _response_prepare */
		rcu_read_unlock();
	}

	return topt;
}
#endif

static int tcp_md5_send_response_prepare(struct sk_buff *orig, u8 flags,
					 unsigned int remaining,
					 struct tcp_out_options *opts,
					 const struct sock *sk,
					 struct tcp_extopt_store *store)
{
#if IS_ENABLED(CONFIG_IPV6)
	if (orig->protocol != htons(ETH_P_IP))
		return tcp_v6_md5_send_response_prepare(orig, flags, remaining,
							opts, sk);
	else
#endif
		return tcp_v4_md5_send_response_prepare(orig, flags, remaining,
							opts, sk);
}

static __be32 *tcp_md5_send_response_write(__be32 *ptr, struct sk_buff *orig,
					   struct tcphdr *th,
					   struct tcp_out_options *opts,
					   const struct sock *sk,
					   struct tcp_extopt_store *store)
{
#if IS_ENABLED(CONFIG_IPV6)
	if (orig->protocol != htons(ETH_P_IP))
		return tcp_v6_md5_send_response_write(ptr, orig, th, opts, sk);
#endif
	return tcp_v4_md5_send_response_write(ptr, orig, th, opts, sk);
}

static struct tcp_md5sig_key *tcp_v4_md5_lookup(const struct sock *sk,
						const struct sock *addr_sk)
{
	const union tcp_md5_addr *addr;

	addr = (const union tcp_md5_addr *)&addr_sk->sk_daddr;
	return tcp_md5_do_lookup(sk, addr, AF_INET);
}

/* Called with rcu_read_lock() */
static bool tcp_v4_inbound_md5_hash(const struct sock *sk,
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
static bool tcp_v6_inbound_md5_hash(const struct sock *sk,
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

static struct tcp_md5sig_key *tcp_v6_md5_lookup(const struct sock *sk,
						const struct sock *addr_sk)
{
	return tcp_v6_md5_do_lookup(sk, &addr_sk->sk_v6_daddr);
}
EXPORT_SYMBOL_GPL(tcp_v6_md5_lookup);
#endif

static bool tcp_inbound_md5_hash(struct sock *sk, const struct sk_buff *skb,
				 struct tcp_options_received *opt_rx,
				 struct tcp_extopt_store *store)
{
	if (skb->protocol == htons(ETH_P_IP)) {
		return tcp_v4_inbound_md5_hash(sk, skb);
#if IS_ENABLED(CONFIG_IPV6)
	} else {
		return tcp_v6_inbound_md5_hash(sk, skb);
#endif
	}

	return false;
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
		struct tcp_md5_extopt *md5_opt;
		struct tcp_md5sig_info *md5sig;
		int err = 0;

		rcu_read_lock();
		md5_opt = tcp_md5_opt_find(sk);
		if (md5_opt) {
			md5sig = rcu_dereference(md5_opt->md5sig_info);
			if (md5sig)
				err = tcp_diag_put_md5sig(skb, md5sig);
		}
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
		struct tcp_md5_extopt *md5_opt;
		const struct tcp_md5sig_info *md5sig;
		const struct tcp_md5sig_key *key;
		size_t md5sig_count = 0;

		rcu_read_lock();
		md5_opt = tcp_md5_opt_find(sk);
		if (md5_opt) {
			md5sig = rcu_dereference(md5_opt->md5sig_info);
			if (md5sig) {
				hlist_for_each_entry_rcu(key, &md5sig->head, node)
					md5sig_count++;
			}
		}
		rcu_read_unlock();
		size += nla_total_size(md5sig_count *
				       sizeof(struct tcp_diag_md5sig));
	}

	return size;
}
EXPORT_SYMBOL_GPL(tcp_md5_diag_get_aux_size);

static int tcp_md5_extopt_add_header_len(const struct sock *orig,
					 const struct sock *sk,
					 struct tcp_extopt_store *store)
{
#if IS_ENABLED(CONFIG_IPV6)
	if (sk->sk_family == AF_INET6 &&
	    !ipv6_addr_v4mapped(&sk->sk_v6_daddr)) {
		if (tcp_v6_md5_lookup(orig, sk))
			return TCPOLEN_MD5SIG_ALIGNED;
	} else
#endif
{
	if (tcp_v4_md5_lookup(orig, sk))
		return TCPOLEN_MD5SIG_ALIGNED;
}

	return 0;
}

static unsigned int tcp_md5_extopt_prepare(struct sk_buff *skb, u8 flags,
					   unsigned int remaining,
					   struct tcp_out_options *opts,
					   const struct sock *sk,
					   struct tcp_extopt_store *store)
{
	int ret = 0;

	if (sk_fullsock(sk)) {
#if IS_ENABLED(CONFIG_IPV6)
		if (sk->sk_family == AF_INET6 && !ipv6_addr_v4mapped(&sk->sk_v6_daddr))
			opts->md5 = tcp_v6_md5_lookup(sk, sk);
		else
#endif
			opts->md5 = tcp_v4_md5_lookup(sk, sk);
	} else {
		struct request_sock *req = inet_reqsk(sk);
		struct sock *listener = req->rsk_listener;
		struct inet_request_sock *ireq = inet_rsk(req);

		/* Coming from tcp_make_synack, unlock is in
		 * tcp_md5_extopt_write
		 */
		rcu_read_lock();

#if IS_ENABLED(CONFIG_IPV6)
		if (ireq->ireq_family == AF_INET6 &&
		    !ipv6_addr_v4mapped(&ireq->ir_v6_rmt_addr))
			opts->md5 = tcp_v6_md5_lookup(listener, sk);
		else
#endif
			opts->md5 = tcp_v4_md5_lookup(listener, sk);

		if (!opts->md5)
			rcu_read_unlock();
	}

	if (unlikely(opts->md5)) {
		ret = TCPOLEN_MD5SIG_ALIGNED;
		opts->options |= OPTION_MD5;

		/* Don't use TCP timestamps with TCP_MD5 */
		if ((opts->options & OPTION_TS)) {
			ret -= TCPOLEN_TSTAMP_ALIGNED;

			/* When TS are enabled, Linux puts the SACK_OK
			 * next to the timestamp option, thus not accounting
			 * for its space. Here, we disable timestamps, thus
			 * we need to account for the space.
			 */
			if (opts->options & OPTION_SACK_ADVERTISE)
				ret += TCPOLEN_SACKPERM_ALIGNED;
		}

		opts->options &= ~OPTION_TS;
		opts->tsval = 0;
		opts->tsecr = 0;

		if (!sk_fullsock(sk)) {
			struct request_sock *req = inet_reqsk(sk);

			inet_rsk(req)->tstamp_ok = 0;
		}
	}

	return ret;
}

static __be32 *tcp_md5_extopt_write(__be32 *ptr, struct sk_buff *skb,
				    struct tcp_out_options *opts,
				    struct sock *sk,
				    struct tcp_extopt_store *store)
{
	if (unlikely(OPTION_MD5 & opts->options)) {
#if IS_ENABLED(CONFIG_IPV6)
		const struct in6_addr *addr6;

		if (sk_fullsock(sk)) {
			addr6 = &sk->sk_v6_daddr;
		} else {
			BUG_ON(sk->sk_state != TCP_NEW_SYN_RECV);
			addr6 = &inet_rsk(inet_reqsk(sk))->ir_v6_rmt_addr;
		}
#endif

		*ptr++ = htonl((TCPOPT_NOP << 24) | (TCPOPT_NOP << 16) |
			       (TCPOPT_MD5SIG << 8) | TCPOLEN_MD5SIG);

		if (sk_fullsock(sk))
			sk_nocaps_add(sk, NETIF_F_GSO_MASK);

		/* Calculate the MD5 hash, as we have all we need now */
#if IS_ENABLED(CONFIG_IPV6)
		if (sk->sk_family == AF_INET6 && !ipv6_addr_v4mapped(addr6))
			tcp_v6_md5_hash_skb((__u8 *)ptr, opts->md5, sk, skb);
		else
#endif
			tcp_v4_md5_hash_skb((__u8 *)ptr, opts->md5, sk, skb);

		ptr += 4;

		/* Coming from tcp_make_synack */
		if (!sk_fullsock(sk))
			rcu_read_unlock();
	}

	return ptr;
}

static struct tcp_md5_extopt *__tcp_md5_extopt_copy(struct request_sock *req,
						    const struct tcp_md5sig_key *key,
						    const union tcp_md5_addr *addr,
						    int family)
{
	struct tcp_md5_extopt *md5_opt = NULL;
	struct tcp_md5sig_info *md5sig;
	struct tcp_md5sig_key *newkey;

	md5_opt = tcp_md5_alloc_store(req_to_sk(req));
	if (!md5_opt)
		goto err;

	md5sig = kmalloc(sizeof(*md5sig), GFP_ATOMIC);
	if (!md5sig)
		goto err_md5sig;

	INIT_HLIST_HEAD(&md5sig->head);
	rcu_assign_pointer(md5_opt->md5sig_info, md5sig);

	newkey = kmalloc(sizeof(*newkey), GFP_ATOMIC);
	if (!newkey)
		goto err_newkey;

	memcpy(newkey->key, key->key, key->keylen);
	newkey->keylen = key->keylen;
	newkey->family = family;
	newkey->prefixlen = 32;
	memcpy(&newkey->addr, addr,
	       (family == AF_INET6) ? sizeof(struct in6_addr) :
				      sizeof(struct in_addr));
	hlist_add_head_rcu(&newkey->node, &md5sig->head);

	return md5_opt;

err_newkey:
	kfree(md5sig);
err_md5sig:
	kfree_rcu(md5_opt, rcu);
err:
	return NULL;
}

static struct tcp_extopt_store *tcp_md5_v4_extopt_copy(const struct sock *listener,
						       struct request_sock *req)
{
	struct inet_request_sock *ireq = inet_rsk(req);
	struct tcp_md5sig_key *key;

	/* Copy over the MD5 key from the original socket */
	key = tcp_md5_do_lookup(listener,
				(union tcp_md5_addr *)&ireq->ir_rmt_addr,
				AF_INET);
	if (!key)
		return NULL;

	return (struct tcp_extopt_store *)__tcp_md5_extopt_copy(req, key,
				(union tcp_md5_addr *)&ireq->ir_rmt_addr,
				AF_INET);
}

#if IS_ENABLED(CONFIG_IPV6)
static struct tcp_extopt_store *tcp_md5_v6_extopt_copy(const struct sock *listener,
						       struct request_sock *req)
{
	struct inet_request_sock *ireq = inet_rsk(req);
	struct tcp_md5sig_key *key;

	/* Copy over the MD5 key from the original socket */
	key = tcp_v6_md5_do_lookup(listener, &ireq->ir_v6_rmt_addr);
	if (!key)
		return NULL;

	return (struct tcp_extopt_store *)__tcp_md5_extopt_copy(req, key,
				(union tcp_md5_addr *)&ireq->ir_v6_rmt_addr,
				AF_INET6);
}
#endif

/* We are creating a new request-socket, based on the listener's key that
 * matches the IP-address. Thus, we need to create a new tcp_extopt_store, and
 * store the matching key in there for the request-sock.
 */
static struct tcp_extopt_store *tcp_md5_extopt_copy(struct sock *listener,
						    struct request_sock *req,
						    struct tcp_options_received *opt,
						    struct tcp_extopt_store *store)
{
#if IS_ENABLED(CONFIG_IPV6)
	struct inet_request_sock *ireq = inet_rsk(req);

	if (ireq->ireq_family == AF_INET6)
		return tcp_md5_v6_extopt_copy(listener, req);
#endif
	return tcp_md5_v4_extopt_copy(listener, req);
}

/* Moving from a request-sock to a full socket means we need to account for
 * the memory and set GSO-flags. When moving from a full socket to ta time-wait
 * socket we also need to adjust the memory accounting.
 */
static struct tcp_extopt_store *tcp_md5_extopt_move(struct sock *from,
						    struct sock *to,
						    struct tcp_extopt_store *store)
{
	struct tcp_md5_extopt *md5_opt = tcp_extopt_to_md5(store);
	unsigned int size = sizeof(struct tcp_md5sig_key);

	if (sk_fullsock(to)) {
		/* From request-sock to full socket */

		if (size > sysctl_optmem_max ||
		    atomic_read(&to->sk_omem_alloc) + size >= sysctl_optmem_max) {
			tcp_md5_extopt_destroy(store);
			return NULL;
		}

		sk_nocaps_add(to, NETIF_F_GSO_MASK);
		atomic_add(size, &to->sk_omem_alloc);
	} else if (sk_fullsock(from)) {
		/* From full socket to time-wait-socket */
		atomic_sub(size, &from->sk_omem_alloc);
	}

	md5_opt->sk = to;

	return store;
}

static void tcp_md5_extopt_destroy(struct tcp_extopt_store *store)
{
	struct tcp_md5_extopt *md5_opt = tcp_extopt_to_md5(store);

	/* Clean up the MD5 key list, if any */
	if (md5_opt) {
		tcp_clear_md5_list(md5_opt);
		kfree_rcu(rcu_dereference_protected(md5_opt->md5sig_info, 1), rcu);
		md5_opt->md5sig_info = NULL;

		kfree_rcu(md5_opt, rcu);
	}
}
