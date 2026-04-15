// rstfilter.c — see rstfilter.h for design notes.

#define _GNU_SOURCE

#include "rstfilter.h"
#include "params.h"
#include "darkmagic.h"

#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#define __FAVOR_BSD
#include <netinet/tcp.h>

// Use the same uthash.h that conntrack.c pulls in, to match project style.
#define HASH_NONFATAL_OOM 1
#undef HASH_FUNCTION
#define HASH_FUNCTION HASH_BER
#include "uthash.h"

// --- Tunables --------------------------------------------------------------

// Flows are considered stale after this many seconds without any packet
// update. A short-lived RST storm against us typically fits in a couple
// of seconds, so 120s is plenty generous while keeping memory bounded.
#define RST_FILTER_IDLE_SEC 120

// TTL delta tolerance. If the RST TTL differs from the stored server
// TTL by more than this, fire heuristic 1. Conservative default of 8
// accommodates legitimate path wobble across ECMP routes. Aggressive
// mode narrows this to 2 — catches more DPI RSTs at the cost of extra
// false-positive risk.
#define RST_FILTER_TTL_TOLERANCE          8
#define RST_FILTER_TTL_TOLERANCE_AGGR     2

// How often the explicit purge walk is allowed to run, in seconds. All
// callers coalesce through this — we do not want to walk the pool on
// every packet.
#define RST_FILTER_PURGE_INTERVAL_SEC     30

// --- Data model ------------------------------------------------------------

typedef struct {
	uint8_t family;            // AF_INET or AF_INET6
	uint8_t _pad[3];
	uint16_t sport;            // client port in host order
	uint16_t dport;            // server port in host order
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
} rst_filter_key;

typedef struct rst_filter_entry {
	rst_filter_key key;
	bool saw_synack;           // server SYN-ACK observed — handshake passed SYN stage
	bool server_responded;     // any non-RST/non-FIN payload-bearing incoming seen
	uint8_t server_ttl;        // heuristic 1 state (0 means unknown)
	uint8_t rst_count;         // heuristic 3 counter
	time_t last_seen;          // for eviction
	UT_hash_handle hh;
} rst_filter_entry;

static rst_filter_entry *pool = NULL;
static time_t last_purge = 0;

// --- Helpers ---------------------------------------------------------------

static int extract_key_incoming(const struct dissect *dis, rst_filter_key *out)
{
	if (!dis || !dis->tcp) return -1;

	memset(out, 0, sizeof(*out));

	// On incoming packets the "server" is dis->ip->ip_src and the
	// "client" is dis->ip->ip_dst. We key by (client_ip, client_port,
	// server_ip, server_port) regardless of direction so that the same
	// entry is reachable from subsequent incoming RSTs on the same
	// 5-tuple.
	if (dis->ip) {
		out->family = AF_INET;
		// Incoming: ip_src = server, ip_dst = client.
		out->addr.v4.src = dis->ip->ip_dst; // client side
		out->addr.v4.dst = dis->ip->ip_src; // server side
		out->sport = ntohs(dis->tcp->th_dport); // dest port of incoming = client port
		out->dport = ntohs(dis->tcp->th_sport); // src port of incoming = server port
	} else if (dis->ip6) {
		out->family = AF_INET6;
		out->addr.v6.src = dis->ip6->ip6_dst; // client side
		out->addr.v6.dst = dis->ip6->ip6_src; // server side
		out->sport = ntohs(dis->tcp->th_dport);
		out->dport = ntohs(dis->tcp->th_sport);
	} else {
		return -1;
	}
	return 0;
}

static size_t key_size(const rst_filter_key *k)
{
	// Hash on the portion of the key that is actually meaningful for
	// its family — the unused address bytes in the union would still
	// hash as zero, but we keep the sizes explicit for clarity.
	(void)k;
	return sizeof(rst_filter_key);
}

static rst_filter_entry *find_or_create(const rst_filter_key *key, bool create)
{
	rst_filter_entry *e = NULL;
	HASH_FIND(hh, pool, key, key_size(key), e);
	if (e || !create) return e;

	e = (rst_filter_entry *)calloc(1, sizeof(*e));
	if (!e) {
		DLOG_ERR("rst_filter: calloc failed\n");
		return NULL;
	}
	e->key = *key;
	HASH_ADD(hh, pool, key, key_size(key), e);
	if (!e->hh.tbl) {
		// uthash in non-fatal OOM mode: if hh.tbl is NULL the add
		// silently failed. Release the orphan and bail.
		free(e);
		return NULL;
	}
	return e;
}

static void purge_if_due(time_t now)
{
	if (now - last_purge < RST_FILTER_PURGE_INTERVAL_SEC) return;
	last_purge = now;

	rst_filter_entry *e, *tmp;
	unsigned int removed = 0;
	HASH_ITER(hh, pool, e, tmp) {
		if (now - e->last_seen > RST_FILTER_IDLE_SEC) {
			HASH_DEL(pool, e);
			free(e);
			removed++;
		}
	}
	if (removed) DLOG("rst_filter: purged %u stale entries\n", removed);
}

static uint8_t current_tolerance(void)
{
	return params.rst_filter == RSTFILTER_AGGRESSIVE
		? RST_FILTER_TTL_TOLERANCE_AGGR
		: RST_FILTER_TTL_TOLERANCE;
}

static inline uint8_t abs_diff(uint8_t a, uint8_t b)
{
	return a > b ? a - b : b - a;
}

// --- Public API ------------------------------------------------------------

void rst_filter_note_incoming(const struct dissect *dis)
{
	if (!dis || !dis->tcp) return;
	if (params.rst_filter == RSTFILTER_OFF) return;

	uint8_t flags = dis->tcp->th_flags;

	// Never treat RST/FIN as "server activity" — those are close
	// semantics, not liveness. Caller already filters RST out; we
	// double-check FIN here for safety.
	if (flags & (TH_RST | TH_FIN)) return;

	rst_filter_key key;
	if (extract_key_incoming(dis, &key) < 0) return;

	time_t now = time(NULL);
	purge_if_due(now);

	rst_filter_entry *e = find_or_create(&key, true);
	if (!e) return;

	// SYN-ACK proves the server accepted the SYN and TCP state passed
	// the first stage. A subsequent RST without any payload activity
	// is then suspicious (see heuristic 2 in rst_filter_should_drop).
	// We must distinguish this from closed-port RSTs where SYN is met
	// by an RST directly — in that case saw_synack stays false and
	// heuristic 2 is suppressed, letting the legit RST through.
	if ((flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK))
		e->saw_synack = true;

	// Payload-bearing incoming packets (data, not bare ACKs) count
	// as "server responded". Used by heuristic 2 as an even stronger
	// signal than SYN-ACK alone.
	if (dis->len_payload > 0)
		e->server_responded = true;

	// Capture the legit server TTL on the first incoming packet so
	// heuristic 1 has a reference to compare against.
	if (!e->server_ttl) e->server_ttl = ttl46(dis->ip, dis->ip6);
	e->last_seen = now;
}

bool rst_filter_should_drop(const struct dissect *dis)
{
	if (params.rst_filter == RSTFILTER_OFF) return false;
	if (!dis || !dis->tcp) return false;

	// Gate: RST flag must be set. Caller should already have checked
	// this — we double-check cheaply to stay safe.
	if (!(dis->tcp->th_flags & TH_RST)) return false;

	rst_filter_key key;
	if (extract_key_incoming(dis, &key) < 0) return false;

	time_t now = time(NULL);
	purge_if_due(now);

	rst_filter_entry *e = find_or_create(&key, true);
	if (!e) return false;

	e->rst_count++;
	e->last_seen = now;

	// ------------------------------------------------------------------
	// Heuristic 2 — RST before any server data, but ONLY after a
	// legitimate SYN-ACK has been observed. Gating on saw_synack is
	// what distinguishes this from legit closed-port RSTs, where the
	// server never sends SYN-ACK at all and must be allowed to refuse
	// the connection cleanly. Once we have SYN-ACK, the flow moved
	// past SYN_SENT and a subsequent RST without any payload is
	// classic DPI mid-handshake injection.
	// ------------------------------------------------------------------
	if (e->saw_synack && !e->server_responded) {
		DLOG("rst_filter: DROP — RST after SYN-ACK but before any "
		     "server data (count=%u)\n", e->rst_count);
		return true;
	}

	// ------------------------------------------------------------------
	// Heuristic 3 — multiple RSTs on same flow in short window.
	// ------------------------------------------------------------------
	if (e->rst_count > 1) {
		DLOG("rst_filter: DROP — multi-RST (count=%u)\n",
		     e->rst_count);
		return true;
	}

	// ------------------------------------------------------------------
	// Heuristic 1 — TTL fingerprint mismatch.
	// ------------------------------------------------------------------
	if (e->server_ttl) {
		uint8_t rst_ttl = ttl46(dis->ip, dis->ip6);
		uint8_t delta = abs_diff(rst_ttl, e->server_ttl);
		if (delta > current_tolerance()) {
			DLOG("rst_filter: DROP — TTL mismatch "
			     "(server=%u rst=%u delta=%u tol=%u)\n",
			     e->server_ttl, rst_ttl, delta,
			     current_tolerance());
			return true;
		}
	}

	return false;
}
