// z2k_tls_mod.h — Phase 8 anti-ТСПУ TLS ClientHello mutation extensions.
//
// Extends upstream's fake_tls_mod with additional JA3-fingerprint-breaking
// modes. All new modes append synthetic TLS extensions to the existing fake
// ClientHello — none of them shift bytes inside the handshake, so the
// implementation is much simpler than the upstream sni mod that had to
// memmove mid-buffer.
//
// The new flag bits occupy the same `mod` field as upstream flags (bit 0x1
// through 0x10 are taken) and this header just extends the set. See
// protocol.h for the canonical FAKE_TLS_MOD_* definitions.
//
// Dispatched from protocol.c's TLSMod() after the upstream mods run, so
// existing sni/rndsni/rnd/dupsid/padencap semantics are unchanged and our
// additions operate on the already-mutated buffer. Safe to combine any
// subset via comma-separated tls_mod= arg.
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

// Apply z2k-extended TLS mod flags to the fake ClientHello buffer.
// `mod_bits` is the bitwise-OR of FAKE_TLS_MOD_* flags. `fake_tls_size`
// and `fake_tls_buf_size` follow the same in/out convention as the
// upstream TLSMod() function — the buffer may grow if we append new
// extensions. Returns true on success (even if no z2k flag was set),
// false if buffer overflow or structural parse failure.
bool z2k_tls_mod_apply(uint32_t mod_bits, uint8_t *fake_tls,
		       size_t *fake_tls_size, size_t fake_tls_buf_size);
