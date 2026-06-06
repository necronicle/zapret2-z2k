-- standard automation/orchestration code
-- this is related to making dynamic strategy decisions without rewriting or altering strategy function code
-- orchestrators can decide which instances to call or not to call or pass them dynamic arguments
-- failure and success detectors test potential block conditions for orchestrators

-- standard host key generator for per-host storage
-- arg: reqhost - require hostname, do not work with ip
-- arg: nld=N - cut hostname to N level domain. NLD=2 static.intranet.microsoft.com => microsoft.com
-- arg: family_split - z2k: isolate rotation state per IP address family. default ON, =0 disables.
function standard_hostkey(desync)
	local hostkey = desync.track and desync.track.hostname
	if hostkey then
		if desync.arg.nld and tonumber(desync.arg.nld)>0 and not (desync.track and desync.track.hostname_is_ip) then
			-- dissect_nld returns nil if domain is invalid or does not have this NLD
			-- fall back to original hostkey if it fails
			local hktemp = dissect_nld(hostkey, tonumber(desync.arg.nld))
			if hktemp then
				hostkey = hktemp
			end
		end
	elseif not desync.arg.reqhost then
		hostkey = host_ip(desync)
	end
	-- z2k per-family rotation isolation (arg: family_split, default ON, =0 to
	-- disable). Append the IP address family to the host key so a path that
	-- fails on one family (e.g. IPv6 ClientHello retransmits to Meta — the host
	-- works over IPv4 via happy-eyeballs) rotates ONLY that family's strategy
	-- and cannot churn the strategy the working family relies on. Placed here in
	-- standard_hostkey (NOT in automate_host_record) so z2k-state-persist's
	-- get_hostkey_func, which calls this function directly to compute the persist
	-- key, derives the SAME suffixed key — keeping state.tsv consistent with the
	-- rotator's autostate[askey][hostkey].
	if hostkey and desync.arg.family_split ~= "0" and desync.dis then
		if desync.dis.ip6 then
			hostkey = hostkey .. "|6"
		elseif desync.dis.ip then
			hostkey = hostkey .. "|4"
		end
	end
	return hostkey
end

-- per-host storage
-- arg: key - a string - table name inside autostate table. to allow multiple orchestrator instances to use single host storage
-- arg: hostkey - hostkey generator function name
function automate_host_record(desync)
	local hostkey, hkf, askey

	if desync.arg.hostkey then
		if type(_G[desync.arg.hostkey])~="function" then
			error("automate: invalid hostkey function '"..desync.arg.hostkey.."'")
		end
		hkf = _G[desync.arg.hostkey]
	else
		hkf = standard_hostkey
	end
	hostkey = hkf(desync)
	if not hostkey then
		DLOG("automate: host record key unavailable")
		return nil
	end

	askey = (desync.arg.key and #desync.arg.key>0) and desync.arg.key or desync.func_instance
	DLOG("automate: host record key 'autostate."..askey.."."..hostkey.."'")
	if not autostate then
		autostate = {}
	end
	if not autostate[askey] then
		autostate[askey] = {}
	end
	if not autostate[askey][hostkey] then
		autostate[askey][hostkey] = {}
	end
	return autostate[askey][hostkey]
end
-- per-connection storage
function automate_conn_record(desync)
	if not desync.track then return nil end
	if not desync.track.lua_state.automate then
		desync.track.lua_state.automate = {}
	end
	return desync.track.lua_state.automate
end

-- counts failure, optionally (if crec is given) prevents dup failure counts in a single connection
-- if 'maxtime' between failures is exceeded then failure count is reset
-- return true if threshold ('fails') is reached
-- hres is host record. host or ip bound table
-- cres is connection record. connection bound table
function automate_failure_counter(hrec, crec, fails, maxtime)
	if crec and crec.failure then
		DLOG("automate: duplicate failure in the same connection. not counted")
	else
		if crec then crec.failure = true end
		local tnow=os.time()
		if not hrec.failure_time_last then
			hrec.failure_time_last = tnow
		end
		if not hrec.failure_counter then
			hrec.failure_counter = 0
		elseif tnow>(hrec.failure_time_last + maxtime) then
			DLOG("automate: failure counter reset because last failure was "..(tnow - hrec.failure_time_last).." seconds ago")
			hrec.failure_counter = 0
		end
		-- z2k: age out a stale success offset. The early per-connection
		-- proof-of-life credit (automate_success_counter) must NOT mask a
		-- fresh failure once the server has stopped responding for >maxtime.
		-- Pruned on the LAST SUCCESS time, independent of the failure stream,
		-- so a working->blocked host loses its offset within one maxtime window.
		if hrec.success_counter and hrec.success_time_last
		   and tnow>(hrec.success_time_last + maxtime) then
			DLOG("automate: success offset reset because last success was "..(tnow - hrec.success_time_last).." seconds ago")
			hrec.success_counter = nil
			hrec.success_time_last = nil
		end
		-- z2k: age out a stale content gate on its OWN (longer) window so a host
		-- that genuinely stops delivering content for the FULL gate window loses
		-- protection and becomes rotatable, while a merely content-quiet working
		-- host (idle < gate window) keeps it.
		local gate_window = Z2K_CONTENT_GATE_WINDOW or 300
		if hrec.content_seen_last and tnow>(hrec.content_seen_last + gate_window) then
			DLOG("automate: content gate aged out (last content "..(tnow - hrec.content_seen_last).."s ago)")
			hrec.content_seen_last = nil
		end
		hrec.failure_counter = hrec.failure_counter + 1
		hrec.failure_time_last = tnow
		local succ = hrec.success_counter or 0
		local net = hrec.failure_counter - succ
		local content_fresh = hrec.content_seen_last and tnow<=(hrec.content_seen_last + gate_window) or false
		if b_debug then DLOG("automate: failure counter "..hrec.failure_counter.."-"..succ.."(succ)=net "..net..(fails and ('/'..fails) or '').." content_fresh="..tostring(content_fresh)) end
		-- z2k option B (dominance) + content gate. Rotate when failures reach the
		-- absolute floor (fails) AND EITHER:
		--   (a) failures strictly out-number live proof-of-life successes
		--       (the r-49 dominance test, UNCHANGED — governs every host that has
		--        delivered real content within the gate window), OR
		--   (b) the host has delivered NO real reverse content on ANY flow within
		--       the gate window (content_fresh==false). This is the handshake-but-
		--       BLOCKED class (whatsapp/Meta): ~150 ServerHellos pump success_counter
		--       but no flow ever crosses Z2K_CONTENT_GATE_BYTES, so the weak
		--       ServerHello flood can no longer protect a strategy that delivers
		--       zero content. The deadlock (succ>=failure forever) is broken.
		-- A tie (failure_counter==succ) on a content-delivering host does NOT
		-- rotate -- benefit of the doubt to a half-alive host. R2/R3 (working
		-- parallel HTTP/2 with retransmit/idle-keepalive noise) keep content_fresh
		-- true via >=1 real content flow, so path (a) governs and succ out-votes
		-- the noise exactly as r-49 designed.
		if fails and hrec.failure_counter>=fails
		   and (hrec.failure_counter>succ or not content_fresh) then
			hrec.failure_counter = nil -- reset counter
			hrec.success_counter = nil -- reset offset together
			hrec.success_time_last = nil
			hrec.content_seen_last = nil -- fresh strategy starts with a clean gate
			return true
		end
	end
	return false
end
-- resets failure counter if it has started counting
function automate_failure_counter_reset(hrec)
	if hrec.failure_counter or hrec.success_counter then
		DLOG("automate: failure/success counter reset")
		hrec.failure_counter = nil
		hrec.success_counter = nil
		hrec.success_time_last = nil
	end
end

-- z2k: credit an EARLY per-connection proof-of-life into the same rolling
-- window the failure counter uses. Deduped per-connection via
-- crec.success_credited (one connection credits at most ONE success, mirroring
-- crec.failure). Touches only host-side fields; never mutates crec.nocheck /
-- crec.failure, so z2k-state-persist accounting is unaffected.
--
-- z2k option B (dominance): success_counter is UNCAPPED. Every connection that
-- shows proof-of-life adds one success to the rolling window, so the tally
-- tracks the real number of live connections. On a working high-parallelism
-- host (Instagram / YouTube HTTP/2: dozens of sockets, each with a ServerHello
-- and/or >512B reverse flight) a minority of retransmitting sockets can no
-- longer out-vote the many that work. The previous (fails-1) clamp neutered
-- proof-of-life on exactly those sites (succ pinned at 2 while per-connection
-- retransmit failures piled up uncapped -> net>=fails -> false rotation of a
-- working strategy). A genuine block still rotates: no proof-of-life keeps succ
-- at 0, and the stale-success aging in automate_failure_counter prunes the
-- offset within one maxtime window when a working host goes dark, restoring
-- failure dominance (see the dominance trigger there). The `fails` arg is no
-- longer used here (kept for call-site signature compatibility).
function automate_success_counter(hrec, crec, fails, maxtime)
	if crec and crec.success_credited then return end
	if crec then crec.success_credited = true end
	local tnow=os.time()
	-- age out a stale failure run before we offset it
	if hrec.failure_counter and hrec.failure_time_last
	   and tnow>(hrec.failure_time_last + maxtime) then
		hrec.failure_counter = nil
	end
	hrec.success_counter = (hrec.success_counter or 0) + 1
	hrec.success_time_last = tnow
	if b_debug then DLOG("automate: success offset "..hrec.success_counter) end
end

-- location is url compatible with Location: header
-- hostname is original hostname
function is_dpi_redirect(hostname, location)
	local ds = dissect_url(location)
	if ds and ds.domain then
		local sld1 = dissect_nld(hostname,2)
		local sld2 = dissect_nld(ds.domain,2)
		return sld2 and sld1~=sld2 and true or false
	end
	return false
end

function standard_detector_defaults(arg)
	return {
		inseq = tonumber(arg.inseq) or 4096,
		retrans = tonumber(arg.retrans) or 3,
		maxseq = tonumber(arg.maxseq) or 32768,
		udp_in = tonumber(arg.udp_in) or 1,
		udp_out = tonumber(arg.udp_out) or 4,
		no_http_redirect = arg.no_http_redirect,
		no_rst = arg.no_rst,
		reset = arg.reset
	}
end

-- standard failure detector
-- works with tcp and udp
-- detected failures:
--   incoming RST
--   incoming http redirection
--   outgoing retransmissions
--   udp too much out with too few in
-- arg: maxseq=<rseq> - tcp: test retransmissions only within this relative sequence. default is 32K
-- arg: retrans=N - tcp: retrans count threshold. default is 3
-- arg: reset - send RST to retransmitter to break long wait
-- arg: inseq=<rseq> - tcp: maximum relative sequence number to treat incoming RST as DPI reset. default is 4K
-- arg: no_http_redirect - tcp: disable http_reply dpi redirect trigger
-- arg: no_rst - tcp: disable incoming RST trigger
-- arg: udp_out - udp: >= outgoing udp packets. default is 4
-- arg: udp_in - udp: with <= incoming udp packets. default is 1
function standard_failure_detector(desync, crec)
	local arg = standard_detector_defaults(desync.arg)
	local trigger = false
	if desync.dis.tcp then
		local seq = pos_get(desync,'s')
		if desync.outgoing then
			if #desync.dis.payload>0 and arg.retrans and arg.maxseq>0 and seq<=arg.maxseq and (crec.retrans or 0)<arg.retrans then
				if is_retransmission(desync) then
					crec.retrans = crec.retrans and (crec.retrans+1) or 1
					DLOG("standard_failure_detector: retransmission "..crec.retrans.."/"..arg.retrans)
					trigger = crec.retrans>=arg.retrans
					if trigger and arg.reset then
						local dis = deepcopy(desync.dis)
						dis.payload = nil
						dis_reverse(dis)
						dis.tcp.th_flags = TH_RST
						dis.tcp.th_win = desync.track and desync.track.pos.reverse.tcp.winsize or 64
						dis.tcp.options = nil
						if dis.ip6 then
							dis.ip6.ip6_flow = (desync.track and desync.track.pos.reverse.ip6_flow) and desync.track.pos.reverse.ip6_flow or 0x60000000;
						end
						DLOG("standard_failure_detector: sending RST to retransmitter")
						rawsend_dissect(dis, {ifout = desync.ifin})
					end
				end
			end
		else
			if not arg.no_rst and arg.inseq>0 and bitand(desync.dis.tcp.th_flags, TH_RST)~=0 and seq>=1 then
				trigger = seq<=arg.inseq
				if b_debug then
					if trigger then
						DLOG("standard_failure_detector: incoming RST s"..seq.." in range s"..arg.inseq)
					else
						DLOG("standard_failure_detector: not counting incoming RST s"..seq.." beyond s"..arg.inseq)
					end
				end
			elseif not arg.no_http_redirect and desync.l7payload=="http_reply" and desync.track.hostname then
				local hdis = http_dissect_reply(desync.dis.payload)
				if hdis and (hdis.code==302 or hdis.code==307) then
					local idx_loc = array_field_search(hdis.headers, "header_low", "location")
					if idx_loc then
						trigger = is_dpi_redirect(desync.track.hostname, hdis.headers[idx_loc].value)
						if b_debug then
							if trigger then
								DLOG("standard_failure_detector: http redirect "..hdis.code.." to '"..hdis.headers[idx_loc].value.."'. looks like DPI redirect.")
							else
								DLOG("standard_failure_detector: http redirect "..hdis.code.." to '"..hdis.headers[idx_loc].value.."'. NOT a DPI redirect.")
							end
						end
					end
				end
			end
		end
	elseif desync.dis.udp then
		if desync.outgoing then
			if arg.udp_out>0 then
				local pos_out = pos_get(desync,'n',false)
				local pos_in = pos_get(desync,'n',true)
				trigger = pos_out>=arg.udp_out and pos_in<=arg.udp_in
				if trigger then
					if b_debug then
						DLOG("standard_failure_detector: arg.udp_out "..pos_out..">="..arg.udp_out.." arg.udp_in "..pos_in.."<="..arg.udp_in)
					end
				end
			end
		end
	end
	return trigger
end

-- standard success detector
-- success means previous failures were temporary and counter should be reset
-- detected successes:
--   tcp: outgoing seq is beyond 'maxseq' and maxseq>0
--   tcp: incoming seq is beyond 'inseq' and inseq>0
--   udp: incoming packets count > `udp_in` and `udp_out`>0
-- arg: maxseq=<rseq> - tcp: success if outgoing relative sequence is beyond this value. default is 32K
-- arg: inseq=<rseq> - tcp: success if incoming relative sequence is beyond this value. default is 4K
-- arg: udp_out - udp : must be nil or >0 to test udp_in
-- arg: udp_in - udp: if number if incoming packets > udp_in it means success
function standard_success_detector(desync, crec)
	local arg = standard_detector_defaults(desync.arg)
	if desync.dis.tcp then
		local seq = pos_get(desync,'s')
		if desync.outgoing then
			if arg.maxseq>0 and seq>arg.maxseq then
				DLOG("standard_success_detector: outgoing s"..seq.." is beyond s"..arg.maxseq..". treating connection as successful")
				return true
			end
		else
			if arg.inseq>0 and seq>arg.inseq then
				DLOG("standard_success_detector: incoming s"..seq.." is beyond s"..arg.inseq..". treating connection as successful")
				return true
			end
		end
	elseif desync.dis.udp then
		if not desync.outgoing then
			local pos = pos_get(desync,'n')
			if arg.udp_out>0 and pos>arg.udp_in then
				if b_debug then
					DLOG("standard_success_detector: arg.udp_in "..pos..">"..arg.udp_in)
				end
				return true
			end
		end
	end

	return false
end

-- z2k: per-host "real content delivered" gate. The STRONG discriminator that
-- separates a handshake-but-BLOCKED host (whatsapp/Meta: every flow stalls at
-- the ~3-5KB cert flight) from a WORKING host (YouTube/Instagram: >=1 flow
-- streams real app data well past the handshake). ServerHello completion and
-- the >512B POL-2 floor are present on BOTH and are therefore WEAK proofs;
-- "reverse content crossed Z2K_CONTENT_GATE_BYTES on at least one flow" happens
-- ONLY on a host that actually delivers content.
--
-- Reads pos_get(desync,'b',true) = per-conntrack cumulative reverse (incoming)
-- bytes (track.pos.reverse.pbcounter) — the SAME signal POL-2 already trusts, so
-- the fix introduces NO new engine signal. Threshold 16384 mirrors silent_drop's
-- bytes_in_handshake_done ("past handshake + first real HTTP/2 app frames");
-- whatsapp's 3-5KB flight never reaches it. Env-tunable for field calibration.
--
-- The gate timestamp ages on its OWN window (Z2K_CONTENT_GATE_WINDOW, default
-- 300s — DECOUPLED from maxtime=60s ON PURPOSE) so a WORKING host that is merely
-- content-quiet for a maxtime window (user reading a page, cached assets) does
-- NOT lose its protection and get false-rotated on a navigation stall. A host
-- that delivers ZERO content for the FULL gate window across ALL flows is the
-- genuine handshake-but-block class and becomes rotatable.
Z2K_CONTENT_GATE_BYTES  = tonumber(os.getenv("Z2K_CONTENT_GATE_BYTES"))  or 16384
Z2K_CONTENT_GATE_WINDOW = tonumber(os.getenv("Z2K_CONTENT_GATE_WINDOW")) or 300
function automate_content_gate(desync, hrec)
	if desync.outgoing or not desync.dis or not desync.dis.tcp then return end
	local b = pos_get(desync,'b',true)
	if b and b > Z2K_CONTENT_GATE_BYTES then
		hrec.content_seen_last = os.time()
		if b_debug then DLOG("automate: content gate set (reverse "..b.."B > "..Z2K_CONTENT_GATE_BYTES..")") end
	end
end

-- z2k: EARLY proof-of-life on an INCOMING packet — the server is responding
-- within ~1 RTT, far before the slow inseq=26000 strong-success. Two signals:
--  POL-1: a structurally VALIDATED incoming TLS ServerHello (same byte-check
--         z2k_tls_stalled trusts) — injected TLS-shaped junk cannot forge it.
--  POL-2: first real reverse data crossed a small floor (512B) a blocked path
--         never reaches but well below inseq=26000 — covers non-TLS / coalesced
--         flights. reverse counters are per-conntrack so a blocked flow reads 0.
-- NOTE: both POL signals stay WEAK (they fire on a handshake-but-blocked host
-- too). They credit success_counter (the dominance vote) and refresh
-- success_time_last EXACTLY as r-49 designed — that refresh is what keeps a
-- WORKING host's offset alive and is NOT touched here. The content gate above
-- is the SEPARATE strong signal that decides the new rotation path.
function automate_proof_of_life(desync)
	if desync.outgoing or not desync.dis or not desync.dis.tcp then return false end
	if desync.l7payload == "tls_server_hello" then
		local p = desync.dis.payload
		if type(p) == "string" and #p >= 60
		   and p:byte(1) == 0x16 and p:byte(2) == 0x03
		   and p:byte(3) >= 0x01 and p:byte(3) <= 0x04
		   and p:byte(6) == 0x02 then
			local rec_len = p:byte(4)*256 + p:byte(5)
			local hs_len  = p:byte(8)*256 + p:byte(9)
			if hs_len > 0 and hs_len + 4 <= rec_len then return true end
		end
	end
	if pos_get(desync,'d',true) >= 1 and pos_get(desync,'b',true) > 512 then
		return true
	end
	return false
end

-- z2k: NATIVE rotation mode (DEFAULT ON). With pure bol-van standard detectors
-- there are no heuristic false-failures to offset, so the r-49 proof-of-life
-- success-offset + content-gate are not only unnecessary — they actively DROWN
-- real RST failures on a handshake-but-blocked host (flibusta-48: 7 real RST
-- fails vs 55 ServerHello "successes" -> net -48 -> never rotates). Native mode
-- DISABLES POL + content-gate so circular rotates on the plain failure count
-- exactly like upstream bol-van. Set Z2K_NATIVE_ROTATION=0 to restore the r-49
-- dominance/POL behaviour (only sensible alongside the custom silent_drop
-- detectors). family-split (standard_hostkey |4/|6) stays ON regardless.
local Z2K_NATIVE_ROTATION = (os.getenv("Z2K_NATIVE_ROTATION") ~= "0")

-- calls success and failure detectors
-- resets counter if success is detected
-- increases counter if failure is detected
-- returns true if failure counter exceeds threshold
function automate_failure_check(desync, hrec, crec)
	if crec.nocheck then return false end

	local failure_detector, success_detector
	if desync.arg.failure_detector then
		if type(_G[desync.arg.failure_detector])~="function" then
			error("automate: invalid failure detector function '"..desync.arg.failure_detector.."'")
		end
		failure_detector = _G[desync.arg.failure_detector]
	else
		failure_detector = standard_failure_detector
	end
	if desync.arg.success_detector then
		if type(_G[desync.arg.success_detector])~="function" then
			error("automate: invalid success detector function '"..desync.arg.success_detector.."'")
		end
		success_detector = _G[desync.arg.success_detector]
	else
		success_detector = standard_success_detector
	end

	local fails = tonumber(desync.arg.fails) or 3
	local maxtime = tonumber(desync.arg.time) or 60

	-- z2k: EARLY per-connection proof-of-life. Credit BEFORE detectors so a
	-- ServerHello arriving on THIS connection offsets its own handshake-time
	-- retransmit failure within the same window. Does NOT latch crec.nocheck
	-- (the strong 26KB success below remains the terminal latch) and does NOT
	-- mutate crec.failure (state-persist accounting untouched).
	if not Z2K_NATIVE_ROTATION then
		-- r-49 counter-measure — custom-detector mode ONLY. Credit early
		-- per-connection proof-of-life (offsets a custom detector's false
		-- handshake-time failure) and track the content gate that the dominance
		-- path in automate_failure_counter consumes. Both are inert/harmful in
		-- native mode (real RST failures must NOT be offset), so they are skipped.
		if automate_proof_of_life(desync) then
			automate_success_counter(hrec, crec, fails, maxtime)
		end
		automate_content_gate(desync, hrec)
	end

	if success_detector(desync, crec) then
		crec.nocheck = true
		DLOG("automate: success detected")
		automate_failure_counter_reset(hrec)
		return false
	end
	if failure_detector(desync, crec) then
		-- z2k: do NOT latch crec.nocheck here. Leaving the connection evaluable
		-- lets its own later ServerHello / 26KB success still credit/reset.
		-- crec.failure (set inside automate_failure_counter) provides the same
		-- one-failure-per-connection dedup the latch used to provide, and the
		-- retrans guard ((crec.retrans or 0)<arg.retrans) prevents any re-RST /
		-- re-count once crec.retrans reaches arg.retrans.
		DLOG("automate: failure detected")
		return automate_failure_counter(hrec, crec, fails, maxtime)
	end

	return false
end


-- circularily change strategy numbers when failure count reaches threshold ('fails')
-- this orchestrator requires redirection of incoming traffic to cache RST and http replies !
-- each orchestrated instance must have strategy=N arg, where N starts from 1 and increment without gaps
-- if 'final' arg is present in an orchestrated instance it stops rotation
-- arg: fails=N - failture count threshold. default is 3
-- arg: time=<sec> - if last failure happened earlier than `maxtime` seconds ago - reset failure counter. default is 60.
-- arg: success_detector - success detector function name
-- arg: failure_detector - failure detector function name
-- arg: hostkey - hostkey generator function name
-- args for failure detector - see standard_failure_detector or your own detector
-- args for success detector - see standard_success_detector or your own detector
-- args for hostkey generator - see standard_hostkey or your own generator
-- test case: --in-range=-s34228 --lua-desync=circular --lua-desync=argdebug:strategy=1 --lua-desync=argdebug:strategy=2
function circular(ctx, desync)
	local function count_strategies(hrec)
		if not hrec.ctstrategy then
			local uniq={}
			local n
			for i,instance in pairs(desync.plan) do
				if instance.arg.strategy then
					n = tonumber(instance.arg.strategy)
					if not n or n<1 then
						error("circular: strategy number '"..tostring(instance.arg.strategy).."' is invalid")
					end
					uniq[tonumber(instance.arg.strategy)] = true
					if instance.arg.final then
						hrec.final = n
					end
				end
			end
			n=0
			for i,v in pairs(uniq) do
				n=n+1
			end
			if n~=#uniq then
				error("circular: strategies numbers must start from 1 and increment. gaps are not allowed.")
			end
			hrec.ctstrategy = n
		end
	end

	-- take over execution. prevent further instance execution in case of error
	orchestrate(ctx, desync)

	if not desync.track then
		DLOG_ERR("circular: conntrack is missing but required")
		return
	end

	local hrec = automate_host_record(desync)
	if not hrec then
		DLOG("circular: passing with no tampering")
		return
	end

	count_strategies(hrec)
	if hrec.ctstrategy==0 then
		error("circular: add strategy=N tag argument to each following instance ! N must start from 1 and increment")
	end
	if not hrec.nstrategy then
		DLOG("circular: start from strategy 1")
		hrec.nstrategy = 1
	end

	local verdict = VERDICT_PASS
	if hrec.final~=hrec.nstrategy then
		local crec = automate_conn_record(desync)
		if automate_failure_check(desync, hrec, crec) then
			hrec.nstrategy = (hrec.nstrategy % hrec.ctstrategy) + 1
			DLOG("circular: rotate strategy to "..hrec.nstrategy)
			if hrec.nstrategy == hrec.final then
				DLOG("circular: final strategy "..hrec.final.." reached. will rotate no more.")
			end
		end
	end

	DLOG("circular: current strategy "..hrec.nstrategy)
	while true do
		local instance = plan_instance_pop(desync)
		if not instance then break end
		if instance.arg.strategy and tonumber(instance.arg.strategy)==hrec.nstrategy then
			verdict = plan_instance_execute(desync, verdict, instance)
		end
	end

	return verdict
end

-- test iff functions
function cond_true(desync)
	return true
end
function cond_false(desync)
	return false
end
-- arg: percent - of true . 50 by default
function cond_random(desync)
	return math.random(0,99)<(tonumber(desync.arg.percent) or 50)
end
-- this iif function detects packets having 'arg.pattern' string in their payload
-- test case : --lua-desync=condition:iff=cond_payload_str:pattern=1234 --lua-desync=argdebug:testarg=1 --lua-desync=argdebug:testarg=2:morearg=xyz
-- test case (true)  : echo aaz1234zzz | ncat -4u 1.1.1.1 443
-- test case (false) : echo aaze124zzz | ncat -4u 1.1.1.1 443
function cond_payload_str(desync)
	if not desync.arg.pattern then
		error("cond_payload_str: missing 'pattern'")
	end
	return desync.dis.payload and string.find(desync.dis.payload,desync.arg.pattern,1,true)
end
-- true if dissect is tcp and timestamp tcp option is present
function cond_tcp_has_ts(desync)
	return desync.dis.tcp and find_tcp_option(desync.dis.tcp.options, TCP_KIND_TS)
end
-- exec lua code in "code" arg and return it's result
function cond_lua(desync)
	if not desync.arg.cond_code then
		error("cond_lua: no 'cond_code' parameter")
	end
	local fname = desync.func_instance.."_cond_cond_code"
	if not _G[fname] then
		local err
		_G[fname], err = load(desync.arg.cond_code, fname)
		if not _G[fname] then
			error(err)
			return
		end
	end
	-- allow dynamic cond_code to access desync
	_G.desync = desync
	local res, v = pcall(_G[fname])
	_G.desync = nil
	if not res then
		error(v);
	end
	return v
end

-- check iff function available. error if not
function require_iff(desync, name)
	if not desync.arg.iff then
		error(name..": missing 'iff' function")
	end
	if type(_G[desync.arg.iff])~="function" then
		error(name..": invalid 'iff' function '"..desync.arg.iff.."'")
	end
end
-- execute further desync instances only if user-provided 'iff' function returns true
-- for example, this can be used by custom protocol detectors
-- arg: iff - condition function. takes desync as arg and returns bool. (cant use 'if' because of reserved word)
-- arg: neg - invert condition function result
-- arg: instances - how many instances execute conditionally. all if not defined
-- test case : --lua-desync=condition:iff=cond_random --lua-desync=argdebug:testarg=1 --lua-desync=argdebug:testarg=2:morearg=xyz
function condition(ctx, desync)
	require_iff(desync, "condition")
	orchestrate(ctx, desync)
	if logical_xor(_G[desync.arg.iff](desync), desync.arg.neg) then
		DLOG("condition: true")
	else
		DLOG("condition: false")
		plan_clear(desync, tonumber(desync.arg.instances))
		if #desync.plan>0 then
			DLOG("condition: executing remaining "..#desync.plan.." instance(s)")
		end
	end
	return replay_execution_plan(desync)
end
-- execute further desync instances.
-- each instance may have "cond" and "cond_neg" args.
-- "cond" - condition function.  "neg" - invert condition function result
-- arg: instances - how many instances execute conditionally. all if not defined
function per_instance_condition(ctx, desync)
	orchestrate(ctx, desync)

	local verdict = VERDICT_PASS
	local n = 0
	local max = tonumber(desync.arg.instances)
	while not max or n<max do
		local instance = plan_instance_pop(desync)
		if not instance then break end
		if instance.arg.cond then
			if type(_G[instance.arg.cond])~="function" then
				error("per_instance_condition: invalid 'iff' function '"..instance.arg.cond.."'")
			end
			-- preapply exec plan to feed cond function correct args
			apply_execution_plan(desync, instance)
			if logical_xor(_G[instance.arg.cond](desync), instance.arg.cond_neg) then
				verdict = plan_instance_execute_preapplied(desync, verdict, instance)
			else
				DLOG("per_instance_condition: condition not satisfied. skipping '"..instance.func_instance.."'")
			end
		else
			DLOG("per_instance_condition: no 'cond' arg in '"..instance.func_instance.."'. skipping")
		end
		n = n + 1
	end
	if #desync.plan>0 then
		DLOG("per_instance_condition: executing remaining "..#desync.plan.." instance(s) unconditionally")
	end
	return verdict_aggregate(verdict, replay_execution_plan(desync))
end

-- clear execution plan if user provided 'iff' functions returns true
-- can be used with other orchestrators to stop execution conditionally
-- arg: iff - condition function. takes desync as arg and returns bool. (cant use 'if' because of reserved word)
-- arg: neg - invert condition function result
-- test case : --in-range=-s1 --lua-desync=circular --lua-desync=stopif:iff=cond_random:strategy=1 --lua-desync=argdebug:strategy=1 --lua-desync=argdebug:strategy=2
function stopif(ctx, desync)
	require_iff(desync, "stopif")
	orchestrate(ctx, desync)
	if logical_xor(_G[desync.arg.iff](desync), desync.arg.neg) then
		DLOG("stopif: true")
		plan_clear(desync)
	else
		-- do not do anything. allow other orchestrator to finish the plan
		DLOG("stopif: false")
	end
end

-- repeat following 'instances' 'repeats' times, execute others with no tampering
-- arg: instances - number of following instances to be repeated. 1 by default
-- arg: repeats - number of repeats
-- arg: iff - condition function to continue execution. takes desync as arg and returns bool. (cant use 'if' because of reserved word)
-- arg: neg - invert condition function result
-- arg: stop - do not replay remaining execution plan after 'instances'
-- arg: clear - clear execution plan after 'instances'
-- test case : --lua-desync=repeater:repeats=2:instances=2 --lua-desync=argdebug:v=1 --lua-desync=argdebug:v=2 --lua-desync=argdebug:v=3
function repeater(ctx, desync)
	local repeats = tonumber(desync.arg.repeats)
	if not repeats then
		error("repeater: missing 'repeats'")
	end
	local iff = desync.arg.iff or "cond_true"
	if type(_G[iff])~="function" then
		error("repeater: invalid 'iff' function '"..iff.."'")
	end
	orchestrate(ctx, desync)
	if #desync.plan==0 then
		DLOG("repeater: execution plan is empty - nothing to repeat")
		return
	end
	local neg = desync.arg.neg
	local stop = desync.arg.stop
	local clear = desync.arg.clear
	local verdict = VERDICT_PASS
	local instances = tonumber(desync.arg.instances) or 1
	local repinst = desync.func_instance
	if instances>#desync.plan then
		instances = #desync.plan
	end
	-- save plan copy
	local plancopy = deepcopy(desync.plan)
	for r=1,repeats do
		if not logical_xor(_G[iff](desync), neg) then
			DLOG("repeater: break by iff")
			break
		end
		DLOG("repeater: "..repinst.." "..r.."/"..repeats)
		-- nested orchestrators can also pop
		local ct_end = #desync.plan - instances
		repeat
			local instance = plan_instance_pop(desync)
			verdict = plan_instance_execute(desync, verdict, instance)
		until #desync.plan <= ct_end
		-- rollback desync plan
		desync.plan = deepcopy(plancopy)
	end
	-- remove repeated instances from desync plan
	for i=1,instances do
		table.remove(desync.plan,1)
	end
	if clear then
		plan_clear(desync)
		return verdict
	elseif stop then
		return verdict
	end
	-- replay the rest
	return verdict_aggregate(verdict, replay_execution_plan(desync))
end
