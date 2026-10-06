# architecture.md — карта проекта

## Компоненты

| Компонент | Файл и функция | Что получает | Что возвращает | В каком потоке |
|---|---|---|---|---|
| Инициализация | `payload.c: inj_init()` (constructor dylib) | — | — | поток dlopen (lldb-инициированный) |
| IPC-сервер | `payload.c: ipc_server_thread/handle_client` | unix-socket `/tmp/inj_ipc_$UID.sock`, одно сообщение на коннект | текстовый ответ | отдельный pthread (один клиент за раз) |
| Диспетчер команд | `payload.c: handle_control_command` | строка команды | ответ или NULL (→Lua exec) | IPC-поток |
| Резолвер символов | `executor_core.cpp: resolve_one/resolve_pipeline_symbol` + `luau_resolver.h` (anchor→xref→prologue по живому образу) | имя символа | runtime-адрес (0 если не найден) | вызывающий поток |
| Версия клиента | `executor_core.cpp: read_client_version/executor_client_version` | Info.plist бинаря | строка версии | любой (лениво, кэш) |
| Скан тредов | `executor_core.cpp: executor_scan_heap` (__SCANL__) | heap-диапазоны | g_live_L[512] + main-кандидаты | IPC-поток (долго: 45–150с) |
| Выбор main | `executor_core.cpp: confirmed_main_thread` | кэш + G-preference | lua_State* main | IPC-поток |
| Компиляция (клиентская) | `executor_core.cpp`: блок fn_init 0x10000c75c + compile-entry 0x10364fdb4 | Lua source | контейнер {module0, module1} (см. ниже: passthrough!) | IPC-поток |
| Компиляция (внешняя, рабочая) | `tools/run741.py: compile_src` → `/tmp/luau-src/build/luau-compile --fflags=false --binary` + `remap()` (upstream→wire опкоды) | Lua source | wire-байткод | процесс python |
| Загрузка чанка | `executor_core.cpp: luau_load` (resolver EXEC_FN_BUfload) на co | wire-байткод | ret=0 / err-строка на стеке | IPC-поток (exec-путь) / игровой поток (hook-путь) |
| Исполнение (старый путь) | `executor_core.cpp: executor_exec_gamestate` → hijack parked co (forge st/ci + gt-swap) → `exec_run` (раннер 0x1026e8df0) | BC:hex или source | pcall=код + строка-результат | IPC-поток |
| Исполнение (новый путь) | `executor_core.cpp: executor_arm + pcall_hook_entry + run_staged_on` | staged blob | rc + g_arm_result | **игровой поток** (внутри luaB_pcall игры) |
| Хук luaB_pcall | `executor_core.cpp: executor_hook_pcall/build_pcall_trampoline` + asm-секция `hook_pad` | patch 4/16 байт на fn | трамплин → `hook_check` | вызывается из всех потоков игры |
| Обработка ошибок | `install_segv_guard/exec_segv_handler` (siglongjmp), `install_alrm_guard` (alarm) | SIGSEGV/SIGBUS/SIGALRM | rc=-4/-2 | контекст сбоявшего потока |
| UI | `ui/server.py` (ThreadingHTTPServer 127.0.0.1) + `ui/index.html` | HTTP | панель | python-процесс |

## Внешние зависимости
- `/tmp/luau-src/build/luau-compile` — единственный рабочий компилятор source→v9 bytecode (клиентский «compile» на 0.741 = passthrough, см. evidence).
- lldb (Xcode) — единственный путь загрузки dylib в живой процесс.
- python3 stdlib only (сокеты) для tools/.

## Генерируемые файлы
- `payload.dylib`, `*.o` (make); `/tmp/inj_payload_<ts>.dylib` (копия для каждого dlopen); лог `/tmp/inj_payload_$UID.log`; сокет; `diagnostics/*` (этот пакет).

## Файлы, используемые скриптами, но отсутствующие в репо
- `/tmp/luau-src/` (клон Luau для компилятора) — НЕ в репо, критично для BC:-режима.
- `/tmp/quick.py`, `/tmp/remap.py` — устаревшие прообразы run741.py (логика перенесена в `tools/run741.py` в этом diff'е).
- `~/roblox_backups/RobloxPlayer.orig-741` — бэкап подписи.

## Различия путей запуска
- `launch_inject.sh` (DYLD_INSERT) — не работает на 0.741 (проверено FINDINGS), оставлен для справки.
- `live_inject.sh` — рабочий путь (lldb dlopen).
- `auto_fly.sh` — устаревший монитор (шлёт fly.lua как plain source; на 0.741 source не компилируется — только BC:).
- Прямая отправка по сокету: `nc -U` или `tools/run741.py exec|arm|...`.

## Ключевые структуры (0.741, выведено и проверено в прошлых сессиях)
- lua_State API-объект 0x88 байт: tt@+1, status@+3, [+0x50]=ci, [+0x58]=base_ci, [+0x60]=base, [+0x68]=G, [+0x70]=top, [+0x78]=stack, [+0x80]=last.
- TValue {value@0, tt(u32)@0xc}, 16 байт. tt: 6=string, 8=closure, 9=Instance, 0xA=thread.
- globals gt @ [L+0x40]; RBX wrapper @ [L+0x48] → [+0x90] security context.
- Wire→internal опкоды: таблица перенумерации лоадера @ file-offset **0x5bed438** (найдена по 10 якорям, уникальное совпадение). Диспатч интерпретатора (internal→handler): link 0x106a31bd0, 256 слотов, 91 непустой; цикл интерпретатора @ link 0x102706664 (`ldrb op; ldr h,[0x106a31bd0+op*8]; br h`).
- luaD_call = link 0x10270af04. Раннер = 0x1026e8df0. Декодер кэша модулей = 0x101448b48. Менеджер кэша модулей = singleton @[0x106c4d4f0+slide] → {array@+8, size@+0x10}.
