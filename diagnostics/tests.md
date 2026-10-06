# tests.md — воспроизводимость сборки и тесты

## Чистая сборка
- Команда: `make clean && make` (лог: `build.log`, exit 0).
- Предупреждения: ~20, все категории pre-existing style (unused vars/functions от выключенных hunter/watchdog, x18 в clobber-листах asm-шимов, sign-compare). Новых предупреждений от deferred-exec кода нет.
- Линкер: `ld: warning: ignoring duplicate libraries: '-lc++'` (безвредно, universal-линк).

## Тесты
| Тест | Команда | Результат | Что доказывает |
|---|---|---|---|
| smoke | `make test` (tools/smoke_test.py) | PASS (5/5) | dylib загружается в сторонний процесс, IPC поднимается, standalone-Lua работает (PING/exec/compile-err/runtime-err/>64KB). **НЕ доказывает** корректность игрового исполнения. |
| resolver selftest | `make resolvetest` | PASS (6/6 anchors + 4/4 derived) | anchor-резолвер находит нужные функции в установленном бинаре 0.741 (lua_newthread/lua_pcall/rawload/compile/luau_load/…). Доказывает только адреса, не исполнение. |

## Дефект сборки (важно)
- **Makefile не отслеживает заголовки**: после `touch executor_core.h` — `make: Nothing to be done`. Объектники НЕ пересобираются при изменении `executor_core.h`/`luau_resolver.h`/`luau_signatures.h`. При смене заголовков нужен `make clean`. (Воспроизведено; команды и вывод в `build.log`/`logs/`.)
- Сборка НЕ зависит от старых артефактов при `make clean` (проверено: clean→build→smoke PASS).

## Примечание по смешению сборок
- В один живой процесс за сессию может быть загружено >1 копии payload.dylib (live_inject всегда копирует файл под новым именем — dlopen старого пути был бы no-op). Старая копия остаётся резидентной; её патчи в коде игры переживают её. До правки stale-hook recovery это дало один фатальный случай «патч на патч» (см. crash/). После правки новая копия обнаруживает чужой патч и переподхватывает его корректно.
