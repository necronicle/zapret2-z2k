-- tests/test_automate_dominance.lua
-- Unit tests for z2k option-B "dominance" rotation in zapret-auto.lua:
--   automate_success_counter  -- success offset is now UNCAPPED
--   automate_failure_counter  -- rotate only when failure_counter>=fails AND
--                                failure_counter>success_counter
--
-- Root cause this guards against: on high-parallelism HTTP/2 hosts
-- (Instagram / YouTube) dozens of sockets each show proof-of-life while a
-- minority retransmit. The old (fails-1) success clamp pinned the offset at 2
-- so per-connection retransmit failures reached net>=fails and false-rotated a
-- working strategy (debug-proven 2026-06-04: rkn_tcp.instagram.com 1->3->4->5).
--
-- Run from the fork root:  lua tests/test_automate_dominance.lua
-- Exit 0 on green, 1 on any failure.

-- ----- mocks ---------------------------------------------------------------
b_debug = false
function DLOG() end

local mock_now = 1000
os.time = function() return mock_now end

-- Load the REAL functions under test from the canonical engine lua.
local here = (arg and arg[0] and arg[0]:match("^(.*)/[^/]*$")) or "."
dofile(here .. "/../lua/zapret-auto.lua")

-- ----- harness -------------------------------------------------------------
local FAILS, MAXTIME = 3, 60
local passed, failed = 0, 0
local function check(name, cond)
  if cond then passed = passed + 1; print("[PASS] " .. name)
  else failed = failed + 1; print("[FAIL] " .. name) end
end

local function new_host() return {} end
-- each call models a DISTINCT connection (fresh crec) unless one is passed in.
-- credit_success models a connection on a WORKING host: it shows proof-of-life
-- (success_counter) AND, because a working host delivers real reverse content,
-- it also refreshes the content gate (hrec.content_seen_last) — exactly what
-- automate_content_gate does in production when a flow crosses
-- Z2K_CONTENT_GATE_BYTES. Without the gate, the content-gated rotation path
-- treats the host as handshake-but-blocked (correct for whatsapp, wrong for a
-- host that genuinely streams content).
local function credit_success(h, crec)
  automate_success_counter(h, crec or {}, FAILS, MAXTIME)
  h.content_seen_last = mock_now            -- working host => content gate fresh
end
-- credit_handshake_only models the whatsapp/Meta R1 class: a connection that
-- completes a TLS handshake (ServerHello -> POL -> success_counter) but whose
-- flow NEVER crosses the content gate. success_counter climbs; content gate
-- stays unset.
local function credit_handshake_only(h, crec)
  automate_success_counter(h, crec or {}, FAILS, MAXTIME)
end
local function record_failure(h, crec) return automate_failure_counter(h, crec or {}, FAILS, MAXTIME) end

-- ----- S1: working high-parallelism host must NOT rotate -------------------
-- 20 connections show proof-of-life, 5 retransmit. With B succ tracks the live
-- connections (uncapped) so 5 failures cannot out-vote 20 successes.
do
  local h = new_host()
  for _ = 1, 20 do credit_success(h) end
  local rotated = false
  for _ = 1, 5 do if record_failure(h) then rotated = true end end
  check("S1 working: 20 succ + 5 fail -> NO rotation", not rotated)
  check("S1 success offset uncapped (==20, old cap was 2)", h.success_counter == 20)
end

-- ----- S2: genuinely blocked host still rotates ----------------------------
do
  local h = new_host()
  local r1 = record_failure(h)
  local r2 = record_failure(h)
  local r3 = record_failure(h)
  check("S2 blocked: 3 fail / 0 succ -> rotate exactly on 3rd",
        (not r1) and (not r2) and (r3 == true))
end

-- ----- S3: a tie does NOT rotate (benefit of the doubt) --------------------
do
  local h = new_host()
  for _ = 1, 3 do credit_success(h) end
  local rotated = false
  for _ = 1, 3 do if record_failure(h) then rotated = true end end
  check("S3 tie: 3 succ + 3 fail -> NO rotation", not rotated)
end

-- ----- S4: failures strictly dominating successes DOES rotate --------------
do
  local h = new_host()
  for _ = 1, 3 do credit_success(h) end
  local res = {}
  for i = 1, 4 do res[i] = record_failure(h) end
  check("S4 dominance: 3 succ + 4 fail -> rotate on 4th (not 3rd)",
        (not res[3]) and (res[4] == true))
end

-- ----- S5: working->blocked, stale success offset is pruned ----------------
-- Successes age out after one maxtime window so a host that goes dark rotates.
do
  local h = new_host()
  for _ = 1, 5 do credit_success(h) end          -- succ=5 at t=1000
  mock_now = 1000 + MAXTIME + 1                   -- >maxtime since last success
  local rotated = false
  for _ = 1, 3 do if record_failure(h) then rotated = true end end
  check("S5 working->blocked: stale success pruned -> rotates", rotated)
  mock_now = 1000                                 -- restore for later tests
end

-- ----- S6: per-connection dedup unchanged ----------------------------------
do
  local h, c = new_host(), {}
  credit_success(h, c); credit_success(h, c)       -- same connection
  check("S6 success dedup: one connection credits once", h.success_counter == 1)
  local h2, c2 = new_host(), {}
  record_failure(h2, c2); record_failure(h2, c2)   -- same connection
  check("S6 failure dedup: one connection counts once", h2.failure_counter == 1)
end

-- ----- S7: rotation resets both counters -----------------------------------
do
  local h = new_host()
  record_failure(h); record_failure(h); record_failure(h)  -- rotates
  check("S7 rotation resets failure+success counters",
        h.failure_counter == nil and h.success_counter == nil)
end

-- ----- S8: regression of the exact field scenario --------------------------
-- The debug log showed "5-2(succ)=net 3/3 -> rotate" ONLY because the cap held
-- succ at 2. Re-credit the real per-connection successes (>=5 here) and the
-- same 5 failures must no longer rotate.
do
  local h = new_host()
  for _ = 1, 6 do credit_success(h) end
  local rotated = false
  for _ = 1, 5 do if record_failure(h) then rotated = true end end
  check("S8 field regression: 6 succ + 5 fail -> NO rotation", not rotated)
end

-- ===========================================================================
-- Content-gated rotation path (whatsapp/Meta handshake-but-block fix).
-- The strong discriminator: a host that delivers NO real reverse content on any
-- flow within the gate window rotates at `fails` REGARDLESS of how many bare
-- ServerHellos pumped success_counter (path b). A host that DID deliver content
-- stays governed by the unchanged r-49 dominance test (path a).
-- ===========================================================================

-- ----- R1: whatsapp handshake-but-block MUST rotate ------------------------
-- Every connection completes a handshake (ServerHello -> success_counter) but
-- NO flow ever crosses the content gate. Under r-49-only this deadlocked
-- (succ>=failure forever, never rotated, ~14h stuck). The content gate (never
-- set) lets path (b) rotate at fails despite succ being high.
do
  local h = new_host()
  for _ = 1, 8 do credit_handshake_only(h) end   -- succ=8, content gate UNSET
  local rotated, at = false, nil
  for i = 1, 3 do if record_failure(h) then rotated = true; at = at or i end end
  check("R1 whatsapp: 8 SH(succ) + 3 mid_stream fail, no content -> ROTATE", rotated)
  check("R1 whatsapp: rotates exactly on the 3rd failure (fails floor)", at == 3)
  check("R1 whatsapp: succ flood did NOT protect a content-dead host",
        h.success_counter == nil)  -- reset on rotate
end

-- ----- R1b: whatsapp that lands on a WORKING strategy stops rotating -------
-- Once a piercing strategy lets a flow cross the content gate, the host is
-- protected on that slot (path a governs, succ dominates).
do
  local h = new_host()
  for _ = 1, 8 do credit_success(h) end          -- now WITH content (working slot)
  local rotated = false
  for _ = 1, 3 do if record_failure(h) then rotated = true end end
  check("R1b working slot: content fresh -> dominance governs -> NO rotation",
        not rotated)
end

-- ----- R2: YouTube/Instagram working w/ retransmit noise -> NO rotation ----
-- Many flows cross the content gate (content_fresh) AND credit succ; a minority
-- of retransmit failures cannot out-vote them and the content-gate bypass does
-- not apply (content is fresh).
do
  local h = new_host()
  for _ = 1, 20 do credit_success(h) end         -- 20 content-bearing flows
  local rotated = false
  for _ = 1, 5 do if record_failure(h) then rotated = true end end
  check("R2 working HTTP/2: 20 content succ + 5 retrans fail -> NO rotation",
        not rotated)
end

-- ----- R3: Instagram working, content-idle for a maxtime window, navigates -
-- The verdict's break against the naive design: content delivered at t=1000,
-- user reads 70s (no >16KB fetch), navigates -> 3 mid_stream fires on idle
-- keep-alive candidates. With the gate window DECOUPLED from maxtime (300s),
-- content_seen_last is still fresh at t=1071, so path (b) does NOT trigger;
-- the dominance path governs and succ (kept fresh by ongoing ServerHellos on
-- new sockets the browser opens) out-votes the 3 idle-stall failures.
do
  local h = new_host()
  for _ = 1, 5 do credit_success(h) end           -- content + succ=5 at t=1000
  mock_now = 1000 + 70                             -- 70s of content-quiet reading
  -- browser opens fresh sockets on navigation -> more ServerHellos keep succ alive
  for _ = 1, 5 do credit_handshake_only(h) end     -- succ=10, content gate NOT refreshed by these
  local rotated = false
  for _ = 1, 3 do if record_failure(h) then rotated = true end end
  check("R3 working idle-70s + navigate: gate window 300s keeps protection -> NO rotation",
        not rotated)
  check("R3 content gate still fresh at +70s (window=300s)",
        h.content_seen_last ~= nil)
  mock_now = 1000
end

-- ----- R3b: gate aging boundary — content-dead for FULL gate window rotates -
-- A host that worked long ago (>gate window) and now delivers zero content is
-- the genuine block class and must become rotatable.
do
  local h = new_host()
  for _ = 1, 5 do credit_handshake_only(h) end     -- succ only, no content
  h.content_seen_last = 1000                        -- worked once, long ago
  mock_now = 1000 + 301                              -- > gate window (300s)
  local rotated = false
  for _ = 1, 3 do if record_failure(h) then rotated = true end end
  check("R3b content gate aged out (>300s) + no fresh content -> ROTATE", rotated)
  mock_now = 1000
end

-- ----- R8: family split — content gate is per-(family-suffixed) hrec --------
-- Modeled by two independent host records: |6 blocked (no content) rotates,
-- |4 working (content fresh) does not. The records never share state.
do
  local h6 = new_host()   -- whatsapp.com|6 — handshake but blocked
  for _ = 1, 6 do credit_handshake_only(h6) end
  local r6 = false
  for _ = 1, 3 do if record_failure(h6) then r6 = true end end

  local h4 = new_host()   -- whatsapp.com|4 — working
  for _ = 1, 6 do credit_success(h4) end
  local r4 = false
  for _ = 1, 3 do if record_failure(h4) then r4 = true end end

  check("R8 family split: blocked |6 rotates", r6)
  check("R8 family split: working |4 does NOT rotate (isolated record)", not r4)
end

-- ----- summary -------------------------------------------------------------
print(("\nResults: %d passed, %d failed"):format(passed, failed))
os.exit(failed == 0 and 0 or 1)
