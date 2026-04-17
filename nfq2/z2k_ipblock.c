// z2k_ipblock.c — see z2k_ipblock.h for design notes.

#define _GNU_SOURCE

#include "z2k_ipblock.h"
#include "params.h"
#include "darkmagic.h"
#include "protocol.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#define __FAVOR_BSD
#include <netinet/tcp.h>

#define HASH_NONFATAL_OOM 1
#undef HASH_FUNCTION
#define HASH_FUNCTION HASH_BER
#include "uthash.h"

// --- Tunables --------------------------------------------------------------

// How many identical ClientHello retransmissions to wait for before
// declaring the server IP dead and sending a client RST. Three is the
// sweet spot — the kernel has already tried twice at that point so the
// TCP stack is convinced the packet is getting through, but the server
// clearly is not responding. Waiting for more retries defeats the
// purpose of fast-fail.
#define Z2K_IPBLOCK_THRESHOLD	3

// How long an idle flow state entry survives in the pool before being
// purged. Generous enough to cover slow page loads, short enough to
// keep memory bounded.
#define Z2K_IPBLOCK_IDLE_SEC	180

// Rate limit for purge walks — we do not want to scan the whole pool
// on every packet.
#define Z2K_IPBLOCK_PURGE_INTERVAL_SEC	30

// Hard cap on flow-state entries. Same rationale as rstfilter.c — an
// unbounded pool under sustained ClientHello-retransmit bursts (e.g.
// heavy page reloads on blocked sites) could grow to megabytes on a
// 64 MB MIPS box. 4096 entries × ~100 B = ~400 KB worst case. Beyond
// the cap we LRU-evict the oldest entry (lowest last_seen) so active
// flows retain their retrans_count through the threshold check, then
// fall back to leaving the new flow untracked rather than risk OOM.
#define Z2K_IPBLOCK_MAX_ENTRIES		4096

// --- Data model ------------------------------------------------------------

typedef struct {
	uint8_t family;
	uint8_t _pad[3];
	uint16_t sport;
	uint16_t dport;
	union {
		struct {
			struct in_addr src;
			struct in_addr dst;
		} v4;
		struct {
			struct in6_addr src;
			struct in6_addr dst;
		} v6;
	} addr;
} z2k_ipblock_key;

typedef struct z2k_ipblock_entry {
	z2k_ipblock_key key;
	uint8_t retrans_count;        // confirmed retransmits seen (upstream detector)
	bool finalized;               // client RST already sent — do not re-fire
	time_t last_seen;
	UT_hash_handle hh;
} z2k_ipblock_entry;

static z2k_ipblock_entry *pool = NULL;
static unsigned int pool_size = 0;
static time_t last_purge = 0;

// --- Helpers ---------------------------------------------------------------

// Build the 4-tuple key for an OUTGOING packet where src=client, dst=server.
static int extract_key_outgoing(const struct dissect *dis, z2k_ipblock_key *out)
{
	if (!dis || !dis->tcp) return -1;
	memset(out, 0, sizeof(*out));
	if (dis->ip) {
		out->family = AF_INET;
		out->addr.v4.src = dis->ip->ip_src;
		out->addr.v4.dst = dis->ip->ip_dst;
		out->sport = ntohs(dis->tcp->th_sport);
		out->dport = ntohs(dis->tcp->th_dport);
	} else if (dis->ip6) {
		out->family = AF_INET6;
		out->addr.v6.src = dis->ip6->ip6_src;
		out->addr.v6.dst = dis->ip6->ip6_dst;
		out->sport = ntohs(dis->tcp->th_sport);
		out->dport = ntohs(dis->tcp->th_dport);
	} else {
		return -1;
	}
	return 0;
}

static void purge_if_due(time_t now)
{
	if (now - last_purge < Z2K_IPBLOCK_PURGE_INTERVAL_SEC) return;
	last_purge = now;

	z2k_ipblock_entry *e, *tmp;
	unsigned int removed = 0;
	HASH_ITER(hh, pool, e, tmp) {
		if (now - e->last_seen > Z2K_IPBLOCK_IDLE_SEC) {
			HASH_DEL(pool, e);
			free(e);
			removed++;
		}
	}
	if (removed) {
		pool_size -= removed;
		DLOG("z2k_ipblock: purged %u stale entries (pool=%u)\n",
		     removed, pool_size);
	}
}

// Remove the single oldest entry (lowest last_seen). Linear scan — only
// invoked when the pool hits the cap, which should be rare under normal
// traffic. Returns true if an entry was freed.
static bool evict_oldest_one(void)
{
	z2k_ipblock_entry *e, *tmp, *victim = NULL;
	HASH_ITER(hh, pool, e, tmp) {
		if (!victim || e->last_seen < victim->last_seen)
			victim = e;
	}
	if (!victim) return false;
	HASH_DEL(pool, victim);
	free(victim);
	pool_size--;
	return true;
}

static z2k_ipblock_entry *find_or_create(const z2k_ipblock_key *key)
{
	z2k_ipblock_entry *e = NULL;
	HASH_FIND(hh, pool, key, sizeof(z2k_ipblock_key), e);
	if (e) return e;

	// Pool cap: force a purge even if not time-due, then LRU-evict if
	// still full. Cold path under normal traffic — purge ticks every
	// 30 s and idle entries age out at 180 s.
	if (pool_size >= Z2K_IPBLOCK_MAX_ENTRIES) {
		last_purge = 0; // force purge_if_due to fire
		purge_if_due(time(NULL));
		while (pool_size >= Z2K_IPBLOCK_MAX_ENTRIES) {
			if (!evict_oldest_one()) break;
		}
		if (pool_size >= Z2K_IPBLOCK_MAX_ENTRIES) {
			// Pool saturated by active flows. Leave the new flow
			// untracked — its retrans will not reach the threshold
			// check, so no RST will be synthesised for it. Graceful
			// feature degradation rather than risking OOM.
			DLOG("z2k_ipblock: pool full (%u), skipping new flow\n",
			     pool_size);
			return NULL;
		}
	}

	e = (z2k_ipblock_entry *)calloc(1, sizeof(*e));
	if (!e) {
		DLOG_ERR("z2k_ipblock: calloc failed\n");
		return NULL;
	}
	e->key = *key;
	HASH_ADD(hh, pool, key, sizeof(z2k_ipblock_key), e);
	if (!e->hh.tbl) {
		free(e);
		return NULL;
	}
	pool_size++;
	return e;
}

// Build a RST packet flowing from the remote server back to the client
// and rawsend it through `ifclient`. Source/dest/seq/ack are taken from
// the outgoing dissect and flipped. Mirrors the upstream pattern at
// desync.c:372-414 inside auto_hostlist_retrans.
static bool send_rst_to_client(const struct dissect *dis,
			       const struct sockaddr *client,
			       const char *ifclient)
{
	uint8_t pkt[sizeof(struct ip6_hdr) + sizeof(struct tcphdr)];
	struct ip *ip = NULL;
	struct ip6_hdr *ip6 = NULL;
	struct tcphdr *tcp;
	size_t pktlen;

	if (!dis || !dis->tcp) return false;

	if (dis->ip) {
		ip = (struct ip *)pkt;
		pktlen = sizeof(struct ip) + sizeof(struct tcphdr);
		*ip = *dis->ip;
		ip->ip_hl = sizeof(struct ip) / 4; // strip options
		ip->ip_len = htons((uint16_t)pktlen);
		ip->ip_id = 0;
		tcp = (struct tcphdr *)(ip + 1);
		*tcp = *dis->tcp;
	} else if (dis->ip6) {
		ip6 = (struct ip6_hdr *)pkt;
		pktlen = sizeof(struct ip6_hdr) + sizeof(struct tcphdr);
		*ip6 = *dis->ip6;
		ip6->ip6_plen = htons((uint16_t)sizeof(struct tcphdr));
		ip6->ip6_nxt = IPPROTO_TCP;
		ip6->ip6_ctlun.ip6_un1.ip6_un1_flow = htonl(0x60000000);
		tcp = (struct tcphdr *)(ip6 + 1);
		*tcp = *dis->tcp;
	} else {
		return false;
	}

	reverse_ip(ip, ip6);          // src<->dst, also fixes IPv4 checksum
	reverse_tcp(tcp);             // sport<->dport, seq<->ack
	tcp->th_off = sizeof(struct tcphdr) / 4; // strip TCP options
	tcp->th_flags = TH_RST;
	tcp->th_win = 0;
	tcp_fix_checksum(tcp, sizeof(struct tcphdr), ip, ip6);

	DLOG("z2k_ipblock: sending RST to client ifname=%s\n",
	     ifclient ? ifclient : "");
	return rawsend(client, 0, ifclient, pkt, pktlen);
}

// Mirror of desync.c's static is_retransmission helper. Kept private to
// this file so it can run without touching upstream's desync.c API.
static inline bool z2k_is_retransmission(const t_ctrack_position *pos)
{
	return !((pos->uppos_prev - pos->pos) & 0x80000000);
}

// --- Public API ------------------------------------------------------------

bool z2k_ipblock_check_outgoing(t_ctrack *ctrack,
				const struct dissect *dis,
				const struct sockaddr *client,
				const char *ifclient)
{
	if (params.z2k_ipblock_detect == Z2K_IPBLOCK_OFF) return false;
	if (!dis || !dis->tcp) return false;
	if (!ctrack) return false;

	// Only act on outgoing packets that actually carry a TLS
	// ClientHello — the whole point is to catch stuck handshakes.
	if (dis->len_payload == 0) return false;
	if (!IsTLSClientHelloPartial(dis->data_payload, dis->len_payload))
		return false;

	// Skip packets that sit in the SYN stage — handshake not even
	// started, nothing to declare blocked yet.
	if (ctrack->pos.state == SYN) return false;

	// Use upstream's retransmission detector on the client-direction
	// position. Avoids the nfqws2 replay mechanism false-positives
	// that a naive seq-equality check would suffer from.
	if (!z2k_is_retransmission(&ctrack->pos.client))
		return false;

	z2k_ipblock_key key;
	if (extract_key_outgoing(dis, &key) < 0) return false;

	time_t now = time(NULL);
	purge_if_due(now);

	z2k_ipblock_entry *e = find_or_create(&key);
	if (!e) return false;

	e->last_seen = now;

	if (e->finalized) {
		// Already fired the client RST on this flow — silent
		// afterwards so we don't spam multiple resets.
		return false;
	}

	e->retrans_count++;
	DLOG("z2k_ipblock: confirmed ClientHello retrans %u/%u\n",
	     e->retrans_count, Z2K_IPBLOCK_THRESHOLD);

	if (e->retrans_count < Z2K_IPBLOCK_THRESHOLD) return false;

	// Threshold reached. Fire the client RST once and mark the
	// entry as finalised so we don't repeat on further retries.
	e->finalized = true;
	if (!send_rst_to_client(dis, client, ifclient)) {
		DLOG_ERR("z2k_ipblock: send_rst_to_client failed\n");
		return false;
	}
	DLOG("z2k_ipblock: fired client RST after %u ClientHello retrans\n",
	     e->retrans_count);
	return true;
}
