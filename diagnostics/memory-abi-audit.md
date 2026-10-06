# memory-abi-audit.md — статический аудит ABI/памяти/восстановления

Классификация: **[src]** подтверждено исходниками, **[diag]** подтверждено диагностикой (логи/отладчик), **[guess]** предположение, **[stale]** устаревшее значение.

## Сигнатуры внешних (клиентских) функций
- `luau_load(L, chunkname, data, size, env)` → int — **[diag]** используется на живом клиенте многократно, ret/стек согласованы.
- `lua_newthread(L)` → L' — **[diag]** работает, top-восстановление после вызова — вручную.
- Раннер 0x1026e8df0(co, from, count) → int — **[diag]** (frame-протокол count=0 верифицирован логами).
- luaD_call 0x10270af04(L, func, nresults) — **[diag]** на hook-пути (rc=0 сериями); граница: Lua-ошибки делают longjmp в игровой protected-фрейм (принято, задокументировано).
- compile-entry 0x10364fdb4 (sret x8, src x0), __init 0x10000c75c (this,ptr,len) — **[diag]** сигнатуры-первые-insn проверяются перед вызовом; НО на 0.741 это passthrough (см. evidence).
- «lua_pcall» резолвера = luaB_pcall (НЕ C-API) — **[diag]** (rc=2 без исполнения closure; тело по дизасму = стек-операции, не запуск).

## Типы/выравнивания
- TValue 16 байт {value@0, tt@0xc} — **[diag]**.
- lua_State 0x88 API-обёртка, поля по оффсетам (см. architecture.md) — **[diag]**.
- std::string (libc++): байт +0x17: бит7 = long-form, иначе short-size — **[diag]** (используется в compile/arm-stage).
- hookpad-секция `.align 12` — **[src]**.

## Указатели / память
- PAC/маскирование: PTR_MASK (36 бит) для const-data указателей — **[diag]**; **НАЙДЕН ДЕФЕКТ**: exec-путь маскирует module-указатель по PTR_MASK и теряет старшие биты кучи (>0x10000000000): «compile empty/oversize» на больших адресах. На hook-пути arm_stage_compile копирует blob через safe_read по СЫРОМУ указателю — корректно. Рекомендация: heap-range-first unmask хелпер. **[diag]**
- safe_read через mach_vm_read_overwrite (никаких голых dereference по игровой памяти) — **[src]**.
- g_arm_bc[65536] статический staging; переполнение отсекает arm_stage_hex (cap check) — **[src]**.
- free() только собственных аллокаций (srcStr long-form); кэш-компиляторские модули не трогаем — **[src]**.
- Буферы ответов IPC: malloc до 32KB, free после write_all — **[src]**; пустой результат → «OK».

## Восстановление состояния
- hijack exec-путь: st/ci/gt restore после run — **[src]**.
- hook-путь: top/gt всегда; ci/base_ci/base дополнительно на fault-пути — **[src+diag]** (до фикса: смерть клиента после contained-SEGV; после: выживает).
- remove_segv_guard: SEGV из old_sa[0], BUS из old_sa[1] — **[src]** (был перепутан — **[diag]** как вклад в «IPC виснет после SEGV»).
- g_pcall_in_hook — реентранс-гард nested-вызовов — **[src]**.

## Предположения о версии клиента
- Все link-time константы (раннер, luaD_call, compile, decoder, module-mgr) жёстко к 0.741: при смене версии — signature-check откажет («drifted») до вызова — **[src]**. luaD_call проверяет только «first insn != 0» — усилить до точного байта. **[src]**
- Резолверские символы (luau_load, lua_newthread, …) — version-agnostic через anchors — **[diag]** (resolvetest PASS).

## Санитайзеры
- Не применялись: переносимых юнитов почти нет (всё завязано на живой процесс). Изолированный стенд trampoline-механики написан и прогнан вручную под lldb (см. summary) — это НЕ live-тест Roblox.
