// z2k_tls_mod.c — see z2k_tls_mod.h for the top-level contract.
//
// Phase 8 of z2k's anti-ТСПУ patch program. Adds four synthetic TLS
// extensions to a fake ClientHello in order to break JA3 / JA3-hash
// fingerprint tables that Russian middleboxes (and other stateful DPI)
// use to classify TLS handshakes:
//
//   GREASE            — inject one extension with a random GREASE-valued
//                       type (RFC 8701). Different value every packet means
//                       per-packet JA3 uniqueness without protocol impact.
//   ALPN flood        — replace / extend ALPN advertisement with ~14 fake
//                       protocols. Most DPI fingerprint sets hash ALPN
//                       order+contents; flooding ALPN invalidates the
//                       hash without preventing h2 negotiation on the wire.
//   PSK exchange      — inject psk_key_exchange_modes (type 0x002d) with
//                       standard modes. TLS 1.3 clients usually omit this
//                       when they do not carry a PSK; adding it makes the
//                       ClientHello look more like a true TLS 1.3 session.
//   key_share         — inject a key_share extension (type 0x0033) with a
//                       random 32-byte x25519 public key. Combines with
//                       psk to push our fingerprint far from the static
//                       byedpi defaults.
//
// Implementation rules:
//   1. Append-only. Extensions are always added at the end of the
//      extensions block, which is also the end of the entire TLS record,
//      so no memmove is needed. This is dramatically simpler than the
//      upstream SNI-replacement path.
//   2. Three length headers are updated after every append: TLS record
//      length (offset 3, u16), handshake length (offset 6, u24), and
//      extensions-block length (offset found via TLSFindExtLen, u16).
//   3. Buffer overflow is checked before every append. Caller provides
//      fake_tls_buf_size and we never grow past it.
//   4. Skipped silently if the buffer is not a valid ClientHello or the
//      extensions block cannot be located — the existing TLSMod() caller
//      already verifies the structure before calling us, but we guard
//      defensively too.

#include "z2k_tls_mod.h"
#include "protocol.h"
#include "helpers.h"
#include "params.h"

#include <string.h>
#include <stdlib.h>

// Bit layout for the 4 new modes. Must not collide with the existing
// upstream FAKE_TLS_MOD_* values (0x01..0x10) defined in protocol.h.
#define FAKE_TLS_MOD_Z2K_GREASE		0x00000020
#define FAKE_TLS_MOD_Z2K_ALPN_FLOOD	0x00000040
#define FAKE_TLS_MOD_Z2K_PSK		0x00000080
#define FAKE_TLS_MOD_Z2K_KEYSHARE	0x00000100

// --- Byte helpers ---------------------------------------------------------

static inline void wr_u16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)(v & 0xff);
}

static inline uint16_t rd_u16(const uint8_t *p)
{
	return ((uint16_t)p[0] << 8) | p[1];
}

static inline uint32_t rd_u24(const uint8_t *p)
{
	return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2];
}

static inline void wr_u24(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)((v >> 16) & 0xff);
	p[1] = (uint8_t)((v >> 8) & 0xff);
	p[2] = (uint8_t)(v & 0xff);
}

// --- Extension presence check --------------------------------------------

// Walks the extensions block of fake ClientHello looking for an extension
// of given type. Returns true if found. RFC 8446 §4.2 strictly forbids
// duplicate extensions in a single ClientHello — server MUST reject with
// "decoded_error" alert. Modern blobs (Chrome / Firefox / Safari) already
// contain ALPN / key_share / psk_key_exchange_modes — appending our z2k_*
// versions without this check produces malformed handshakes that strict
// peers (Cloudflare прежде всего) reject silently.
static bool z2k_tls_has_ext(const uint8_t *fake_tls, size_t fake_tls_size,
			    size_t extlen_offset, uint16_t ext_type)
{
	if (extlen_offset + 2 > fake_tls_size) return false;
	uint16_t ext_block_len = rd_u16(fake_tls + extlen_offset);
	const uint8_t *p = fake_tls + extlen_offset + 2;
	const uint8_t *end = p + ext_block_len;
	if (end > fake_tls + fake_tls_size) end = fake_tls + fake_tls_size;
	while (p + 4 <= end) {
		uint16_t type = rd_u16(p);
		uint16_t len  = rd_u16(p + 2);
		if (type == ext_type) return true;
		if (p + 4 + len > end) break;
		p += 4 + len;
	}
	return false;
}

// --- Core append helper ---------------------------------------------------

// Append a single TLS extension (type + length + data) to the end of the
// fake ClientHello's extensions block and update the three length headers.
// Returns true on success, false on overflow / parse failure.
//
// `extlen_offset` is passed in from the dispatcher so the caller can
// amortise one TLSFindExtLen() scan across multiple appends. The
// extensions-block starts at a fixed offset inside the handshake (after
// the ClientVersion/Random/SessionID/CipherSuites/CompressionMethods
// fields), so appending new extensions never shifts that offset — only
// the length value at extlen_offset needs to be bumped.
static bool z2k_tls_append_ext(uint8_t *fake_tls,
			       size_t *fake_tls_size,
			       size_t fake_tls_buf_size,
			       size_t extlen_offset,
			       uint16_t ext_type,
			       const uint8_t *ext_data,
			       size_t ext_data_len)
{
	size_t add = 4 + ext_data_len; // 2 bytes type + 2 bytes length + data
	size_t new_size = *fake_tls_size + add;

	if (new_size > fake_tls_buf_size) {
		DLOG_ERR("z2k_tls_mod: overflow appending ext type=0x%04x "
			 "size=%zu buf=%zu\n", ext_type, new_size,
			 fake_tls_buf_size);
		return false;
	}

	// Append at the current buffer tail — extensions are the final
	// field in the ClientHello, so appending byte-extends the record.
	uint8_t *tail = fake_tls + *fake_tls_size;
	wr_u16(tail + 0, ext_type);
	wr_u16(tail + 2, (uint16_t)ext_data_len);
	if (ext_data_len)
		memcpy(tail + 4, ext_data, ext_data_len);

	// Update all three length headers.
	uint16_t rec_len = rd_u16(fake_tls + 3);
	wr_u16(fake_tls + 3, (uint16_t)(rec_len + add));

	uint32_t hs_len = rd_u24(fake_tls + 6);
	wr_u24(fake_tls + 6, hs_len + (uint32_t)add);

	uint16_t ext_block_len = rd_u16(fake_tls + extlen_offset);
	wr_u16(fake_tls + extlen_offset, (uint16_t)(ext_block_len + add));

	*fake_tls_size = new_size;
	return true;
}

// --- Individual modes -----------------------------------------------------

// GREASE extension type values follow RFC 8701 pattern 0xNANA where N
// is one of 0,1,2,...,F. We pick a random nibble per call.
static uint16_t random_grease_value(void)
{
	static const uint16_t grease_table[] = {
		0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
		0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA
	};
	return grease_table[random() & 0xF];
}

static bool z2k_tls_mod_grease(uint8_t *fake_tls, size_t *fake_tls_size,
			       size_t fake_tls_buf_size,
			       size_t extlen_offset)
{
	// Two random padding bytes as body. Keeps the extension short and
	// RFC-compliant — servers always ignore GREASE values.
	uint8_t data[2];
	data[0] = (uint8_t)(random() & 0xff);
	data[1] = (uint8_t)(random() & 0xff);
	bool ok = z2k_tls_append_ext(fake_tls, fake_tls_size,
				     fake_tls_buf_size, extlen_offset,
				     random_grease_value(),
				     data, sizeof(data));
	if (ok) DLOG("z2k_tls_mod: applied grease\n");
	return ok;
}

static bool z2k_tls_mod_alpn_flood(uint8_t *fake_tls, size_t *fake_tls_size,
				   size_t fake_tls_buf_size,
				   size_t extlen_offset)
{
	// RFC 8446 §4.2: duplicate extensions of same type are illegal — strict
	// peers (Cloudflare) reject with decode_error alert. Chrome/Firefox/Safari
	// blobs already advertise ALPN, so silently skip if present.
	if (z2k_tls_has_ext(fake_tls, *fake_tls_size, extlen_offset, 0x0010)) {
		DLOG("z2k_tls_mod: skip alpn_flood — ALPN already in ClientHello\n");
		return true;
	}

	// Build ALPN ext body: u16 list_length, then N strings each with a
	// u8 length prefix. 14 protocols is enough to dramatically distort
	// any fingerprint that hashes ALPN list+order.
	static const char *protos[] = {
		"h2", "http/1.1", "spdy/3.1", "spdy/3", "spdy/2",
		"h3", "h3-32", "h3-29", "h3-27", "http/0.9",
		"http/1.0", "webrtc", "c-webrtc", "acme-tls/1"
	};
	uint8_t body[256];
	size_t off = 2; // reserve list_length u16
	for (size_t i = 0; i < sizeof(protos) / sizeof(*protos); i++) {
		size_t plen = strlen(protos[i]);
		if (off + 1 + plen > sizeof(body)) break;
		body[off++] = (uint8_t)plen;
		memcpy(body + off, protos[i], plen);
		off += plen;
	}
	wr_u16(body, (uint16_t)(off - 2));

	bool ok = z2k_tls_append_ext(fake_tls, fake_tls_size,
				     fake_tls_buf_size, extlen_offset,
				     0x0010, // application_layer_protocol_negotiation
				     body, off);
	if (ok) DLOG("z2k_tls_mod: applied alpn_flood (%zu protocols)\n",
		     sizeof(protos) / sizeof(*protos));
	return ok;
}

static bool z2k_tls_mod_psk(uint8_t *fake_tls, size_t *fake_tls_size,
			    size_t fake_tls_buf_size,
			    size_t extlen_offset)
{
	// RFC 8446 §4.2 duplicate-check (see z2k_tls_mod_alpn_flood).
	if (z2k_tls_has_ext(fake_tls, *fake_tls_size, extlen_offset, 0x002d)) {
		DLOG("z2k_tls_mod: skip psk — psk_key_exchange_modes already in ClientHello\n");
		return true;
	}

	// psk_key_exchange_modes body: u8 ke_modes_length, then ke_modes.
	// Mode 0x00 = psk_ke, 0x01 = psk_dhe_ke (TLS 1.3 standard).
	uint8_t body[3];
	body[0] = 0x02; // ke_modes length
	body[1] = 0x00; // psk_ke
	body[2] = 0x01; // psk_dhe_ke

	bool ok = z2k_tls_append_ext(fake_tls, fake_tls_size,
				     fake_tls_buf_size, extlen_offset,
				     0x002d, // psk_key_exchange_modes
				     body, sizeof(body));
	if (ok) DLOG("z2k_tls_mod: applied psk (key exchange modes)\n");
	return ok;
}

static bool z2k_tls_mod_keyshare(uint8_t *fake_tls, size_t *fake_tls_size,
				 size_t fake_tls_buf_size,
				 size_t extlen_offset)
{
	// RFC 8446 §4.2 duplicate-check.
	if (z2k_tls_has_ext(fake_tls, *fake_tls_size, extlen_offset, 0x0033)) {
		DLOG("z2k_tls_mod: skip keyshare — key_share already in ClientHello\n");
		return true;
	}

	// key_share extension body:
	//   u16 client_shares_len
	//   [
	//     u16 group (0x001d = x25519)
	//     u16 key_exchange_len
	//     <key_exchange>
	//   ]
	// We advertise one entry with a random x25519 public key.
	//
	// RFC 7748 §5: x25519 public keys MUST be clamped — random 32 bytes
	// is invalid as Curve25519 point and strict TLS 1.3 implementations
	// reject the handshake. Apply standard clamp:
	//   key[0]  &= 0xF8   (clear bottom 3 bits)
	//   key[31] &= 0x7F   (clear top bit)
	//   key[31] |= 0x40   (set second-top bit)
	// Result is a uniformly-random scalar in the valid x25519 subset.
	// Server actually computes ECDH against this, but since we only care
	// the handshake passes the syntactic gate (protocol-level cap from
	// our fake never reaches server's crypto layer due to badsum/tcp_md5),
	// any clamped 32-byte value works.
	uint8_t body[2 + 2 + 2 + 32];
	uint8_t key[32];
	for (size_t i = 0; i < sizeof(key); i++)
		key[i] = (uint8_t)(random() & 0xff);
	key[0]  &= 0xF8;
	key[31] &= 0x7F;
	key[31] |= 0x40;

	wr_u16(body + 0, 2 + 2 + 32);   // client_shares_len
	wr_u16(body + 2, 0x001d);       // group x25519
	wr_u16(body + 4, 32);           // key_exchange_len
	memcpy(body + 6, key, 32);

	bool ok = z2k_tls_append_ext(fake_tls, fake_tls_size,
				     fake_tls_buf_size, extlen_offset,
				     0x0033, // key_share
				     body, sizeof(body));
	if (ok) DLOG("z2k_tls_mod: applied keyshare (clamped x25519)\n");
	return ok;
}

// --- Public dispatcher ----------------------------------------------------

bool z2k_tls_mod_apply(uint32_t mod_bits, uint8_t *fake_tls,
		       size_t *fake_tls_size, size_t fake_tls_buf_size)
{
	if (!fake_tls || !fake_tls_size) return false;

	// Fast path: no z2k flags set, nothing to do. Returning true keeps
	// the dispatch chain transparent for strategies that only use
	// upstream modes.
	const uint32_t z2k_mask = FAKE_TLS_MOD_Z2K_GREASE
				| FAKE_TLS_MOD_Z2K_ALPN_FLOOD
				| FAKE_TLS_MOD_Z2K_PSK
				| FAKE_TLS_MOD_Z2K_KEYSHARE;
	if (!(mod_bits & z2k_mask)) return true;

	// We only extend valid ClientHellos; the upstream TLSMod path
	// already verified this before calling us, but belt-and-suspenders.
	if (!IsTLSClientHello(fake_tls, *fake_tls_size, false)) {
		DLOG_ERR("z2k_tls_mod: buffer is not a valid ClientHello\n");
		return false;
	}

	// Locate the extensions-length field once and thread it through the
	// mod chain. Extensions live at a fixed offset inside the ClientHello
	// record (after Version / Random / SessionID / CipherSuites /
	// CompressionMethods), and appending new extensions never moves that
	// offset — only the u16 value at it changes. Before this cache each
	// mod re-walked the record via TLSFindExtLen(); with all 4 flags set
	// that was 4× redundant scans per fake packet on the MIPS hot path.
	size_t extlen_offset = 0;
	if (!TLSFindExtLen(fake_tls, *fake_tls_size, &extlen_offset)) {
		DLOG_ERR("z2k_tls_mod: cannot locate extensions length\n");
		return false;
	}

	if (mod_bits & FAKE_TLS_MOD_Z2K_GREASE)
		if (!z2k_tls_mod_grease(fake_tls, fake_tls_size,
					fake_tls_buf_size, extlen_offset))
			return false;

	if (mod_bits & FAKE_TLS_MOD_Z2K_ALPN_FLOOD)
		if (!z2k_tls_mod_alpn_flood(fake_tls, fake_tls_size,
					    fake_tls_buf_size, extlen_offset))
			return false;

	if (mod_bits & FAKE_TLS_MOD_Z2K_PSK)
		if (!z2k_tls_mod_psk(fake_tls, fake_tls_size,
				     fake_tls_buf_size, extlen_offset))
			return false;

	if (mod_bits & FAKE_TLS_MOD_Z2K_KEYSHARE)
		if (!z2k_tls_mod_keyshare(fake_tls, fake_tls_size,
					  fake_tls_buf_size, extlen_offset))
			return false;

	return true;
}
