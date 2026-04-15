// rstfilter.h — drop DPI-injected fake TCP RST packets
//
// Phase 6B of the z2k anti-ТСПУ patch program. The main Lua hook surface
// of zapret2 does not dispatch lua_desync action functions on incoming
// direction packets, so a pure-Lua RST drop is not possible. This module
// installs a C-level hook inside dpi_desync_packet_play() that inspects
// incoming TCP RST packets and decides whether to drop them based on
// three independent heuristics. Any one trigger is sufficient.
//
// Heuristic 1 — TTL fingerprint mismatch
//   Store the TTL of the first incoming payload-bearing packet per flow
//   as the "legit server TTL". On a subsequent incoming RST, compare its
//   TTL against the stored value; a delta greater than `tolerance` means
//   the RST was crafted from a different hop count than real server
//   traffic — classic signature of an injected fake.
//
// Heuristic 2 — RST before any server response
//   A real server cannot reset a connection before it has sent at least
//   one byte of data (or a SYN-ACK). If we see an incoming RST on a flow
//   that has not yet seen any non-RST server payload, that is almost
//   certainly a DPI reset.
//
// Heuristic 3 — Multi-RST on one connection
//   A real TCP close sends a single RST. Seeing two or more RSTs on the
//   same flow within a short window is a DPI retransmission pattern.
//
// Connection state is kept in a standalone uthash pool keyed on the
// 4-tuple (src_ip, src_port, dst_ip, dst_port) with family discriminator.
// Eviction is time-based, driven by periodic purge calls that walk the
// pool and drop entries idle beyond `RST_FILTER_IDLE_SEC`.
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "darkmagic.h"

enum rst_filter_mode {
	RSTFILTER_OFF = 0,
	RSTFILTER_ON,
	RSTFILTER_AGGRESSIVE,
};

// Returns true if the incoming TCP RST carried in `dis` looks like a fake
// from DPI according to the three-check heuristic. Caller should honor
// the return by turning the packet into VERDICT_DROP.
//
// Only meant to be called with incoming TCP RST packets — the caller in
// dpi_desync_packet_play() guards both conditions before dispatching.
// Internally time-evicts stale state, so no external init/purge is
// required. Pool starts empty via C static zero-init.
bool rst_filter_should_drop(const struct dissect *dis);

// Records a legitimate incoming TCP packet (non-RST) to update per-flow
// state:
//   - sets `server_responded = true` when the packet has a payload
//     (for heuristic 2)
//   - captures the current TTL as `server_ttl` on first sighting
//     (for heuristic 1)
// Called from dpi_desync_packet_play() on every incoming non-RST TCP
// packet when rst_filter is enabled.
void rst_filter_note_incoming(const struct dissect *dis);
