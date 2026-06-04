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
-- each call models a DISTINCT connection (fresh crec) unless one is passed in
local function credit_success(h, crec) automate_success_counter(h, crec or {}, FAILS, MAXTIME) end
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

-- ----- summary -------------------------------------------------------------
print(("\nResults: %d passed, %d failed"):format(passed, failed))
os.exit(failed == 0 and 0 or 1)
