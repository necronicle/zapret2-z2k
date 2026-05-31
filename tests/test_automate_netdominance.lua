-- Unit tests for the net-dominance + proof-of-life rotation fix in zapret-auto.lua.
-- Drives automate_failure_check(desync, hrec, crec) directly with mocked detectors.
-- A "connection" = one crec; a "host" = one hrec shared across its connections.

local NOW = 1000
os.time = function() return NOW end
DLOG = function() end
b_debug = false
-- per-conntrack reverse counters for POL-2 (pos_get(d,kind,reverse))
function pos_get(d, k, rev)
  local t = rev and d._rev or d._fwd
  return (t and t[k]) or 0
end
-- mock detectors, driven by desync flags
function mock_fail(d, crec) return d._fail == true end
function mock_succ(d, crec) return d._strong == true end

dofile("lua/zapret-auto.lua")

local P,F = 0,0
local function ck(name, want, got)
  if want==got then P=P+1; print("[PASS] "..name)
  else F=F+1; print(string.format("[FAIL] %s: want=%s got=%s", name, tostring(want), tostring(got))) end
end

local ARG = {failure_detector="mock_fail", success_detector="mock_succ", fails=3, time=60}
local function mk_fail()   return { outgoing=true,  dis={tcp={}}, arg=ARG, _fail=true } end
local function mk_strong() return { outgoing=false, dis={tcp={}}, arg=ARG, _strong=true } end
local function mk_sh()
  local p = string.char(0x16,0x03,0x03,0x00,0x50,0x02,0x00,0x00,0x4c)..string.rep(string.char(0),60)
  return { outgoing=false, l7payload="tls_server_hello", dis={tcp={}, payload=p}, arg=ARG }
end
local function mk_pol2()   return { outgoing=false, dis={tcp={}}, arg=ARG, _rev={d=2,b=900} } end
-- fire one packet on (hrec, crec); returns true if it caused a ROTATE
local function pkt(mkfn, hrec, crec) return automate_failure_check(mkfn(), hrec, crec) == true end

-- T1 blocked cold: 3 conns each 1 failure, no response -> rotate on 3rd
do local h={}
  ck("T1 blocked: A.fail no rotate", false, pkt(mk_fail,h,{}))
  ck("T1 blocked: B.fail no rotate", false, pkt(mk_fail,h,{}))
  ck("T1 blocked: C.fail ROTATES",   true,  pkt(mk_fail,h,{}))
end

-- T2 v6 transient: each conn fail then ServerHello -> never rotate
do local h={}
  local a,b,c={},{},{}
  pkt(mk_fail,h,a); pkt(mk_sh,h,a)
  pkt(mk_fail,h,b); pkt(mk_sh,h,b)
  ck("T2 v6: C.fail after 2 SH credits no rotate", false, pkt(mk_fail,h,c))
  pkt(mk_sh,h,c)
  ck("T2 v6: success_counter capped at fails-1=2", 2, h.success_counter)
end

-- T3 worst interleave: all fail before any SH -> rotate once then settle
do local h={}
  pkt(mk_fail,h,{}); pkt(mk_fail,h,{})
  ck("T3 worst: 3rd fail ROTATES once", true, pkt(mk_fail,h,{}))
  ck("T3 worst: counters reset after rotate", nil, h.failure_counter)
end

-- T4 partial degrade: 1 working (fail+SH) + 4 blocked -> rotate
do local h={}
  local w={}
  pkt(mk_fail,h,w); pkt(mk_sh,h,w)   -- working: counter=1, succ=1
  pkt(mk_fail,h,{})                  -- B1 counter=2 net=1
  pkt(mk_fail,h,{})                  -- B2 counter=3 net=2
  ck("T4 partial: majority-blocked ROTATES", true, pkt(mk_fail,h,{}))  -- B3 counter=4 net=3
end

-- T5 working->blocked: success offset ages out after maxtime
do local h={}
  NOW=1000
  local w1,w2={},{}
  pkt(mk_fail,h,w1); pkt(mk_sh,h,w1)
  pkt(mk_fail,h,w2); pkt(mk_sh,h,w2)
  ck("T5 succ=2 after two SH", 2, h.success_counter)
  NOW=1200   -- >maxtime(60) past last success(1000) -> offset prunes on next failure
  pkt(mk_fail,h,{})  -- prune: succ->nil, counter=1
  ck("T5 offset pruned", nil, h.success_counter)
  pkt(mk_fail,h,{})  -- counter=2
  ck("T5 blocked after prune ROTATES at fails", true, pkt(mk_fail,h,{}))
end

-- T6 no double-count: same crec failing twice counts once
do local h={}
  local a={}
  pkt(mk_fail,h,a)
  pkt(mk_fail,h,a)  -- crec.failure dedups
  ck("T6 same conn counted once", 1, h.failure_counter)
end

-- T7 strong 26KB success fully resets both halves
do local h={}
  local a={}
  pkt(mk_fail,h,a)
  ck("T7 pre: counter=1", 1, h.failure_counter)
  pkt(mk_strong,h,a)  -- success_detector true -> reset
  ck("T7 strong success nils failure_counter", nil, h.failure_counter)
  ck("T7 strong success nils success_counter", nil, h.success_counter)
end

-- T8 POL-2 (non-TLS reverse floor) credits success
do local h={}
  local a={}
  pkt(mk_fail,h,a)         -- counter=1
  pkt(mk_pol2,h,a)         -- POL-2 reverse>512 -> succ credit
  ck("T8 POL-2 credits success_counter", 1, h.success_counter)
end

print(string.format("\n%d passed, %d failed", P, F))
os.exit(F==0 and 0 or 1)
