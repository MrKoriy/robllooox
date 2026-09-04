# ЗАДАЧА: Roblox Script Executor для macOS (executor-core)

## Цель
Скрипт-экзекутор для живых игр Roblox на macOS (Apple Silicon): исполнение
Lua/Luau-кода в РОДНОМ Luau-state клиента игры, с identity уровня, достаточного
для `game:GetService`, `Instance.new`, `RunService.Heartbeat` (боевой скрипт — fly).

## Что уже есть (стартовая точка)
- Рабочий dylib-инжектор в `~/Documents/coding/vibecoded/inj/`:
  - `payload.c` — constructor + pthread + `luaL_dofile("/tmp/rbx_script.lua")`
  - `launch_inject.sh` — DYLD_INSERT_LIBRARIES при запуске
  - `live_inject.sh` — lldb + dlopen в живой процесс
- Ограничение: создаёт СВОЙ чистый `lua_State` — нет `game`/`workspace`.
  Требуется исполнение в state ИГРЫ.
- Боевой скрипт: `fly.lua` (та же папка).

## ЭТАП 1 — Разведка
1. Исходники Luau (github.com/luau-lang/luau):
   - структуры `lua_State`, `global_State`
   - где живут thread identity / capabilities (Luau::Security, extraspace)
   - сигнатуры `luau_load` / load-функций
2. Клиент Roblox.app на macOS:
   - состав бинаря и Frameworks, как устроен ScriptContext
   - классические точки: `RBX::TaskScheduler` → ScriptContext → `lua_State*`
   - как определить версию клиента (version guid) — оффсеты привязываются к ней
3. Защита (Hyperion на macOS):
   - codesign validation, `PT_DENY_ATTACH`, integrity checks
   - свежие публичные writeups (дата критична — методы живут неделями)
4. Open-source экзекуторы (архитектура, НЕ оффсеты):
   - как делают signature scanning, компиляцию Luau, подъём identity
5. Инструменты: Ghidra/IDA/Hopper (статика), lldb (динамика), vmmap.

## ЭТАП 2 — Получить lua_State игры (ключевой результат)
- Signature scanner внутри payload.dylib: найти по байт-паттернам в __TEXT:
  - load-функцию Luau
  - доступ к ScriptContext / global state
- АЛЬТЕРНАТИВА (устойчивее к обфускации): хук на функцию scheduler'а,
  которая регулярно получает `lua_State*` (heartbeat), перехват state оттуда.
- КРИТЕРИЙ: из нашего кода внутри процесса получить валидный `lua_State*` игры
  и прочитать глобаль `game` без краша.

## ЭТАП 3 — Execution primitive
- Поднять identity текущего потока (изучить, где Roblox хранит её в thread).
- Исполнение: вызвать игровой `luau_load` (Этап 2), либо слинковать открытый
  luau-compile и подать байткод в игровую load-функцию.
- Обёртка `execute(source) -> ok/err`, ошибки печатать в stdout.

## ЭТАП 4 — Интеграция
- payload.dylib: найти state → дождаться загрузки DataModel → execute
  `/tmp/rbx_script.lua` → hot-reload по изменению файла (nice to have).
- Путь инжекта без debugger (чистый DYLD_INSERT_LIBRARIES) — приоритет.

## ЭТАП 5 — Приёмка
- `fly.lua` работает в живой игре: E вкл/выкл, WASD/Space/Shift, 10 мин без краша.
- Тесты ТОЛЬКО на отдельном аккаунте (бан-риск — факт жизни, не обсуждается).

## ЖЕЛЕЗНЫЕ ПРАВИЛА ДЛЯ ИСПОЛНИТЕЛЯ
1. ЗАПРЕЩЕНО выдумывать адреса, оффсеты, сигнатуры. Каждое значение —
   из реального бинаря ТЕКУЩЕЙ версии (Ghidra + lldb), верифицировано
   в отладчике. Нет верификации — нет значения.
2. Оффсеты ломаются с каждым апдейтом Roblox → приложить инструкцию,
   как обновить сигнатуры под новую версию.
3. Hyperion — итеративный противник: сначала работа без обхода,
   обход отдельным этапом, честно документировать, что детектится.
4. Результат: заметки по версии клиента + код executor-core (C/ObjC),
   интегрированный в payload.dylib.
