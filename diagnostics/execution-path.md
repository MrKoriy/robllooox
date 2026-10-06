# execution-path.md — путь одного запроса (текущая сборка, dirty-diff)

## Путь A: `run741.py exec '...'` (BC: через старый exec-путь)

1. **Приём**: `payload.c: ipc_server_thread → handle_client` — читает всё до EOF (grow-buffer), RCVTIMEO 15с. Один запрос = одна сессия сокета. Владелец буфера `buf` — handle_client (free на выходе).
2. **Разбор**: `handle_control_command` — точные префиксы `__CMD__`; иначе Lua. `BC:<hex>` проходит как «Lua» вниз в `execute_lua_code` → `executor_exec_gamestate` (host_is_roblox).
3. **Компиляция**: source-режим — клиентский compile-entry 0x10364fdb4 (на 0.741 = passthrough → детектор «compiler is dead» → ERR). BC:-режим — hex→bytes в `executor_exec_gamestate` (malloc, free после).
4. **Преобразование**: внешнее (python `run741.py remap()`: upstream→wire по WIRE-таблице, aux-aware обход; НЕ в процессе).
5. **Выбор состояния/треда**: `confirmed_main_thread` (кэш+валидация; при протухании — G-preference по g_live_L без полного рескана); затем `exec_pick_parked_game_co` (st=1 предпочтительно, st=0 с extraspace-эвристикой) — иначе `exec_newthread(main)`.
6. **Загрузка**: `luau_load(co, "INJ", bc, len, 0)` под SEGV/ALRM-гардами (alarm 15с).
7. **Исполнение**: hijack-протокол на parked co (forge status=0, ci=base_ci, gt-swap [co+0x40]→raw-gt main'а) → `exec_run(co,0)` (раннер 0x1026e8df0 → rawrunprotected). Исключения: сигнатуры fn_init/ccompile/runner проверяются по первым insn перед вызовом.
8. **Результат/ошибка**: `extract_top_string(co)` (строка в top-1..8, tt=6, len≤600) → «pcall=N err/result="…"». run=2 → ERRRUN с текстом.
9. **Очистка**: restore hijacked co (st/ci/gt) сразу после exec_run; guards сняты (remove_alrm/remove_segv — **после фикса remove_segv_guard восстанавливает SEGV/BUS из правильных слотов**). source-string `srcStr` freed при long-form. co НЕ освобождается (утечка допустима — GC игры).
10. **Ответ**: `write_all` + close.

## Путь B: `run741.py arm/poll/rearm` (deferred-exec через pcall-хук) — НОВЫЙ

1. Приём/разбор: IPC, `__ARM__ <src|BC:hex>`.
2. Компиляция: `arm_stage_compile` (клиентский compile — бесполезен на 0.741) или `arm_stage_hex` (BC:hex → staging-буфер `g_arm_bc[65536]`, копия — кэш-компилятор не может перетереть). Владелец: статический буфер до следующего arm.
3. Установка хука: `executor_hook_pcall(fn)`:
   - проверка stale-патча (если fn уже пропатчен прежней копией: recovery оригинальных 4 insn из старого трамплина +0x34 и re-point .quad — **патчи не стакаются**);
   - mprotect hookpad RW (наша __TEXT-секция), fn-страница через VM_PROT_COPY (arm64 отказывает plain RW на коде);
   - wide-патч 16 байт `ldr x16,#8; br x16; .quad tramp` (entry-инструкция пишется последней), либо BL (4 байта, атомарно) при дистанции ≤±128MB;
   - clear_cache, mprotect RX обратно.
4. Арминг: `g_arm_state=ARM_ARMED` (release). **Владелец исполнения — игровой поток.**
5. Выбор потока: `hook_check(x0=L,…,999)` на КАЖДОМ входе luaB_pcall → `pcall_hook_entry`: фильтр tt=0xA, G == g_arm_g_filter (0 → g_main_G, 1 = любая вселенная); CAS ARM_ARMED→ARM_BUSY (single-shot).
6. Загрузка+исполнение: `run_staged_on(L)` на игровом потоке: save top/ci/base_ci/base/gt (+gt-swap на raw-gt main при наличии); `luau_load(L,"INJARM",bc,len,0)`; `luaD_call(L, top-16, -1)` (0x10270af04+slide). Гарды SEGV/ALRM на этом потоке; реентрантность хука глушится `g_pcall_in_hook`.
7. Результат: rc + `arm_set_result` (vsnprintf в `g_arm_result[4096]`) + slot-dump в лог. **Известный дефект: строка-результат luaD_call не извлекается (см. evidence).**
8. Очистка: restore top/gt всегда; при fault — дополнительно ci/base_ci/base (иначе игра падает на dead frame — проверено крашем до фикса). Гарды сняты. state=ARM_DONE (release).
9. Ответ: немедленный «ARMED…»; результат — отдельным `__POLL__`.
10. Повтор: `__REARM__` (без перекомпиляции). Снятие: `__DISARM__` (state=IDLE + restore 16 байт fn).

## Ограничения времени жизни / синхронизация
- g_exec_jmp/g_exec_segv/g_exec_timeout — ГЛОБАЛЬНЫЕ (один активный guarded-участок за раз — фактически сериализовано IPC-потоком; hook-путь работает на игровом потоке и НЕ должен пересекаться с exec-путём во времени — операторская дисциплина, не enforced).
- Сигнальные обработчики — process-wide: на окно guarded-участка SEGV/BUS любой другой нити тоже приземлятся в наш handler (принятый риск, окно короткое).
- Сокет single-threaded accept-loop: длинные операции (полный scan) блокируют ответы (см. threading-ipc.md).
