-- Юнит-тест вето по доставленному контенту (lua/zapret-auto.lua).
-- Запуск: lua lua/test-content-veto.lua
--
-- Сторожим ровно контракт вето, а не работу детекторов: живой хост, недавно
-- отдавший контент, по порогу провалов НЕ ротируется; он же с протухшим
-- контентом — ротируется; хост, не отдавший ничего, ротируется как раньше.
-- Повод — ложная ротация instagram.com 30.08 по трём входящим RST при
-- работающем сайте (404831 байт на обоих плечах).

local PASS, FAIL = 0, 0
local function ok(m) PASS = PASS + 1; print("[PASS] " .. m) end
local function no(m, want, got)
    FAIL = FAIL + 1
    print(string.format("[FAIL] %s (want=%s got=%s)", m, tostring(want), tostring(got)))
end
local function is(m, want, got) if want == got then ok(m) else no(m, want, got) end end

-- ----- заглушки движка -------------------------------------------------------
function DLOG() end
b_debug = false
local FAKE_NOW = 1000000
local real_time = os.time
os.time = function() return FAKE_NOW end
local SERVER_BYTES = 0
function pos_get_pos(t, mode) if t == "SRV" and mode == 'b' then return SERVER_BYTES end end

-- загружаем файл под тестом, отрезав всё, что требует движка при загрузке
local src = io.open((arg and arg[0] or ""):gsub("test%-content%-veto%.lua$", "") .. "zapret-auto.lua")
              or io.open("lua/zapret-auto.lua")
assert(src, "не найден zapret-auto.lua")
local chunk = assert(load(src:read("a"), "zapret-auto"))
chunk()
src:close()

local function hrec_with(content_age)
    local h = {}
    if content_age then h.content_seen_last = FAKE_NOW - content_age end
    return h
end
local function three_failures(h)
    local r
    for _ = 1, 3 do r = automate_failure_counter(h, nil, 3, 60) end
    return r
end

-- ----- сам контракт ----------------------------------------------------------
is("хост без контента ротируется по порогу", true, three_failures(hrec_with(nil)))
is("свежий контент (10 с) ротацию ВЕТИРУЕТ", false, three_failures(hrec_with(10)))
is("контент на границе окна (299 с) ещё ветирует", false, three_failures(hrec_with(299)))
is("протухший контент (301 с) ротацию НЕ ветирует", true, three_failures(hrec_with(301)))

-- вето обязано обнулять счётчик, иначе печаталось бы на каждый пакет
local h = hrec_with(10)
three_failures(h)
is("после вето счётчик обнулён", nil, h.failure_counter)

-- гейт взводится ровно при превышении порога и берёт СЕРВЕРНЫЙ счётчик
local g = {}
SERVER_BYTES = Z2K_CONTENT_GATE_BYTES
z2k_content_gate({ track = { pos = { server = "SRV" } } }, g)
is("ровно порог гейт не взводит", nil, g.content_seen_last)
SERVER_BYTES = Z2K_CONTENT_GATE_BYTES + 1
z2k_content_gate({ track = { pos = { server = "SRV" } } }, g)
is("порог+1 гейт взводит", FAKE_NOW, g.content_seen_last)
local g2 = {}
z2k_content_gate({ track = nil }, g2)
is("без conntrack гейт молчит и не падает", nil, g2.content_seen_last)

os.time = real_time
print(string.format("\nPASSED: %d\nFAILED: %d", PASS, FAIL))
os.exit(FAIL == 0 and 0 or 1)
