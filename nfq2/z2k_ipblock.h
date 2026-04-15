// z2k_ipblock.h — Phase 9 anti-ТСПУ IP block detection + fast client RST.
//
// When a target IP is partially blocked (e.g. a specific Cloudflare edge
// node silently drops traffic mid-handshake), a TCP client will retransmit
// its ClientHello until the OS gives up. User-facing behaviour: page
// "loading" for 30+ seconds then failing. Applications typically have
// *several* A-records available for the same hostname and would benefit
// from a fast retry on a different IP if we short-circuited the timeout.
//
// This module watches for repeated ClientHello retransmits on the same
// 4-tuple and, once a threshold is reached, synthesises a TCP RST from
// server → client and raw-sends it via the client interface. The client
// kernel delivers ECONNRESET to the app, which immediately re-resolves
// and tries the next A-record. Much faster than waiting for the kernel
// SYN/data retransmission timeout to elapse.
//
// Not to be confused with Phase 6B (rstfilter) which does the opposite —
// it drops INCOMING fake RSTs from DPI. This one generates OUTGOING
// RSTs to the local client under a clear error condition.

#pragma once

#include <stdbool.h>
#include <sys/socket.h>

#include "darkmagic.h"

enum z2k_ipblock_mode {
	Z2K_IPBLOCK_OFF = 0,
	Z2K_IPBLOCK_ON,
};

// Called from the outgoing-packet path in desync.c on every outgoing
// TCP packet from a ClientHello-carrying flow. Examines whether the
// current packet is a ClientHello retransmission; if so, increments a
// per-flow counter and, once the threshold is crossed, fabricates an
// RST packet flowing from the remote server back to `client` and
// sends it via `ifclient`.
//
// Safe to call on every outgoing TCP packet — fast-path returns when
// the module is disabled, when the packet is not a ClientHello, or
// when the flow was already finalised. The caller does NOT need to
// pre-check retransmission.
//
// Return value: true if a client RST was just sent (caller may choose
// to DROP the current outgoing packet to stop further retransmits
// propagating), false otherwise.
bool z2k_ipblock_check_outgoing(const struct dissect *dis,
				const struct sockaddr *client,
				const char *ifclient);
