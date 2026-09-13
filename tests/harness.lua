-- Synthetic C runtime/packets. The Lua library, detectors and circular are real.
local H = { now=1000, timers={}, sent={}, passed=0, failed=0 }
if _VERSION >= "Lua 5.3" then
    bitand, bitnot, bitxor = assert(load("return function(a,b) return a & b end, function(a) return ~a end, function(a,b) return a ~ b end"))()
else
    local bit = require('bit')
    bitand, bitnot, bitxor = bit.band, bit.bnot, bit.bxor
end
getpid, gettid = function() return 1 end, function() return 1 end
clock_gettime = function() return 1, 1 end
clock_getfloattime = function() return H.now end
os.time = function() return math.floor(H.now) end
u32add = function(a,b) return (a+b)%4294967296 end
NFQWS2_COMPAT_VER=6
TH_FIN,TH_SYN,TH_RST,TH_PUSH,TH_ACK=1,2,4,8,16
VERDICT_PASS=0
DLOG,DLOG_ERR=function() end,function() end
local here = debug.getinfo(1,'S').source:sub(2):match('^(.*)/[^/]+$')
dofile(here..'/../lua/zapret-lib.lua')
dofile(here..'/../lua/zapret-auto.lua')
rawsend_dissect=function(dis) H.sent[#H.sent+1]=dis; return true end
orchestrate=function() end
plan_instance_pop=function(d) d.cursor=(d.cursor or 0)+1; return d.plan[d.cursor] end
plan_instance_execute=function(_d,v,instance) H.executed=tonumber(instance.arg.strategy); return v end
timer_set=function(name,func,period,oneshot,data)
    assert(oneshot and period>=10)
    H.timers[name]={func=func,due=H.now+period/1000,data=data}
end
timer_del=function(name) H.timers[name]=nil end
function H.advance(seconds)
    local finish=H.now+seconds
    while true do
        local name, timer
        for n,t in pairs(H.timers) do
            if t.due<=finish and (not timer or t.due<timer.due) then name,timer=n,t end
        end
        if not timer then break end
        H.now=timer.due; H.timers[name]=nil
        local callback=type(timer.func)=="function" and timer.func or _G[timer.func]
        callback(name,timer.data)
    end
    H.now=finish
end
function H.track(host) return {hostname=host or 'review.example',lua_state={}} end
function H.tcp(track,out,seq,payload,l7,retrans)
    track=track or H.track()
    payload=payload or ''
    track.pos={direct={tcp={rseq=seq,pos=seq+#payload,uppos_prev=retrans and seq+#payload or seq}},
        reverse={tcp={rseq=1,winsize=65535}}}
    return {track=track,outgoing=out,l7payload=l7 or 'unknown',
        arg={key='rkn_tcp',nld='2',fails='3',time='60',inseq='4096',maxseq='32768',retrans='3',reset=true},
        dis={ip={ip_ttl=52},tcp={th_flags=#payload>0 and 24 or 16},payload=payload}}
end
function H.udp(track,out,payload,l7,nout,nin)
    track=track or H.track()
    track.pos={direct={pcounter=out and (nout or 1) or (nin or 1)},reverse={pcounter=out and (nin or 0) or (nout or 1)}}
    return {track=track,outgoing=out,l7payload=l7 or 'unknown',
        arg={key='yt_quic',nld='2',fails='3',time='60',udp_in='1',udp_out='5'},
        dis={ip={ip_ttl=52},udp={},payload=payload}}
end
function H.step(d)
    d.cursor=nil
    d.plan={{arg={strategy='1'}},{arg={strategy='2'}},{arg={strategy='3'}}}
    circular(nil,d)
    return automate_host_record(d),d.track.lua_state.automate
end
function H.reset() autostate={}; H.now=1000; H.timers={}; H.sent={}; H.executed=nil end
function H.eq(want,got)
    assert(want==got,'expected '..tostring(want)..', got '..tostring(got))
end
function H.test(name,fn)
    H.reset()
    local ok,err=pcall(fn)
    if ok then H.passed=H.passed+1; print('[PASS] '..name)
    else H.failed=H.failed+1; print('[FAIL] '..name..': '..tostring(err)) end
end
function H.finish()
    print(string.format('\nPASSED: %d\nFAILED: %d',H.passed,H.failed))
    os.exit(H.failed==0 and 0 or 1)
end
return H
