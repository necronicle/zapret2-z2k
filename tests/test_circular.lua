local here=arg[0]:match('^(.*)/[^/]+$') or '.'
local H=dofile(here..'/harness.lua')
H.test('detector is pure, reset follows accepted failure exactly once',function()
    local d=H.tcp(nil,true,1,'request',nil,true)
    local c={}
    for i=1,3 do standard_failure_detector(d,c) end
    H.eq(0,#H.sent)
    for i=1,4 do H.step(d) end
    H.eq(1,#H.sent); H.eq(TH_RST,H.sent[1].tcp.th_flags)
end)
H.test('vetoed retransmission remains detectable without side effects',function()
    function test_veto(d,c) standard_failure_detector(d,c); return false,'pending' end
    local d=H.tcp(nil,true,1,'request',nil,true); d.arg.failure_detector='test_veto'
    for i=1,3 do H.step(d) end
    H.eq(0,#H.sent)
    d.arg.failure_detector=nil
    local h,c=H.step(d)
    H.eq(true,c.failure); H.eq(1,h.failure_counter); H.eq(1,#H.sent)
end)
H.test('flow keeps its strategy when other flows rotate the host',function()
    local d=H.tcp(nil,true,1,'request')
    local h,c=H.step(d)
    circular_rotate(h)
    H.step(H.tcp(d.track,true,1,'request',nil,true))
    H.eq(1,H.executed); H.eq(1,c.nstrategy); H.eq(2,h.nstrategy)
end)
H.test('old successes cannot clear current failures',function()
    local d=H.tcp(nil,true,1,'request'); local h=H.step(d)
    circular_rotate(h); h.failure_counter=2
    H.step(H.tcp(d.track,false,4201,'content'))
    H.eq(2,h.failure_counter)
end)
H.test('old failures cannot send RST or penalize the next strategy',function()
    local d=H.tcp(nil,true,1,'request',nil,true); local h=H.step(d)
    H.step(d); circular_rotate(h)
    H.step(d); H.eq(0,#H.sent); H.eq(nil,h.failure_counter)
end)
H.test('wraparound does not revive old generation',function()
    local d=H.tcp(nil,true,1,'request'); local h,c=H.step(d)
    for i=1,3 do circular_rotate(h) end
    H.eq(1,h.nstrategy); H.eq(false,circular_attempt_current(h,c))
    H.eq(false,circular_report_failure(h,c,{fails=1})); H.eq(nil,c.failure)
end)
H.test('nine asynchronous old-flow failures rotate only once',function()
    local records,h={},nil
    for i=1,9 do local c; h,c=H.step(H.udp(nil,true,'x')); records[i]=c end
    for _,c in ipairs(records) do circular_report_failure(h,c,{fails=3,time=60}) end
    H.eq(2,h.nstrategy); H.eq(nil,h.failure_counter)
end)
H.test('current success resets accumulated failures',function()
    local d=H.tcp(nil,true,1,'request'); local h=H.step(d); h.failure_counter=2
    local _,c=H.step(H.tcp(d.track,false,4201,'content'))
    H.eq(true,c.nocheck); H.eq(nil,h.failure_counter)
end)
H.test('RST/FIN/empty/repeated packets alone are not byte successes',function()
    for _,flags in ipairs({TH_RST+TH_ACK,TH_FIN+TH_ACK,TH_ACK}) do
        local d=H.tcp(nil,false,4201,''); d.dis.tcp.th_flags=flags
        H.eq(false,standard_success_detector(d,{}))
    end
    H.eq(false,standard_success_detector(H.tcp(nil,false,4201,'x',nil,true),{}))
end)
H.test('a profile/host change gets independent connection state',function()
    local d=H.tcp(nil,true,1,'request'); local h,c=H.step(d); c.nocheck=true
    d.track.hostname='other.invalid'; local other,cc=H.step(d)
    assert(other~=h and cc~=c); H.eq(nil,cc.nocheck)
end)
H.test('final/manual pin stops pending timers and overrides the flow plan',function()
    local d=H.tcp(nil,true,1,'request'); local h,c=H.step(d)
    h.nstrategy=2; h.final=2; H.step(d)
    H.eq(2,H.executed); H.eq(false,circular_report_failure(h,c,{fails=1})); H.eq(nil,h.failure_counter)
end)
H.test('neutral observations do not clear failures',function()
    function test_neutral() return false,'neutral' end
    local d=H.tcp(nil,true,1,'request'); local h=H.step(d); h.failure_counter=2
    d.arg.failure_detector='test_neutral'; local _,c=H.step(d)
    H.eq(true,c.neutral); H.eq(2,h.failure_counter)
end)
H.test('invalid detector names fail visibly',function()
    local d=H.tcp(nil,true,1,'request'); d.arg.failure_detector='missing_detector'
    H.eq(false,pcall(H.step,d))
end)
H.test('retrans=0 disables retransmission failures',function()
    local d=H.tcp(nil,true,1,'request',nil,true); d.arg.retrans='0'
    H.eq(false,standard_failure_detector(d,{}))
end)
H.test('invalid persisted strategy is normalized before binding or execution',function()
    local d=H.tcp(nil,true,1,'request'); local h=automate_host_record(d); h.nstrategy=99
    local _,c=H.step(d); H.eq(1,H.executed); H.eq(1,c.nstrategy)
end)
H.test('async result honors state reconciliation and rotation notifies persistence',function()
    local h,c=H.step(H.udp(nil,true,'x')); local notifications=0
    h.on_strategy_changed=function() notifications=notifications+1 end
    circular_report_failure(h,c,{fails=1}); H.eq(1,notifications)
    local _,nextc=H.step(H.udp(nil,true,'x'))
    h.before_async_result=function(rec) rec.final=rec.nstrategy end
    H.eq(false,circular_report_failure(h,nextc,{fails=1})); H.eq(1,notifications)
end)
H.finish()
