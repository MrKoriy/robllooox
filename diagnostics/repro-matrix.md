# repro-matrix.md — минимальная матрица воспроизведения

Клиент 0.741.0.7411056, сборка dirty-diff (sha256 dylib 73d23561…), путь: pcall-hook deferred-exec (`tools/run741.py arm|poll`), вселенная — игровая (пин через probe `game.Players.LocalPlayer.Name`: rc=0 только в игре).
Каждый вход — `diagnostics/repro/rN_*.lua`; внешняя компиляция `luau-compile --fflags=false --binary` + wire-ремaп (`tools/run741.py`).

| ID | Вход | Ожидалось | Фактически | Лог | Сбой |
|---|---|---|---|---|---|
| R1 | `return 1` | rc=0 | rc=0 | fires, dcall ok | нет |
| R2 | `local a=6 local b=7 return a*b` | rc=0 (MUL) | rc=0 | fires, dcall ok | нет |
| R3 | `return ("abc"):upper()` | rc=0 | rc=0 | dcall ok | нет |
| R4 | `local f=function(x) return x end return f("ok")` | rc=0 (DUPCLOSURE) | rc=0 | dcall ok | нет |
| R5 | `return game.Workspace.Name` | rc=0 + "Workspace" | rc=0, извлечено 'Workspace' | fslot STR | нет |
| R6 | `return game.Workspace:FindFirstChild("Baseplate")` | rc=0 | rc=0 (извлечённая строка — соседний слот, см. дефект извлечения) | fslot STR | нет |
| R7 | `game.Workspace.Gravity = 50` | известный проблемный случай | **rc=0, запись принята, клиент жив**; обратная запись 196.2 тоже rc=0 | fired rc=0 ×2 | **нет на hook-пути** |
| R8 | `repro/r8_pulse_fails_load.lua` (5 statement'ов с MULK×3 + SETTABLEKS) | rc=0 | **rc=-21: «bytecode corrupted» при загрузке** | fired rc=-21 | load-отказ (не краш) |

## Пояснения
- R7 — «известный проблемный случай» из FINDINGS (SEGV на exec-пути). На pcall-hook-пути запись проходит — барьер снят контекстом. **Строгое доказательство разницы путей.**
- R8 — активный дефект сборки чанка: фрагменты пульса по отдельности грузятся (проверено bisect'ом шестью подчанками, все rc=0), полная связка — нет. Подозрение: aux-разметка ремаппера (`AUX_OPS` в run741.py устарел относительно `getOpLength()` Luau: NEWTABLE/SETLIST/FORGLOOP/LOADKX/FASTCALL2/FASTCALL2K/FASTCALL3/JUMPXEQK*/GETUDATAKS/SETUDATAKS/NAMECALLUDATA/… имеют aux; рассинхрон середины потока смещает все последующие опкоды).
- Извлечение результата (строки) на hook-пути неточное: R5 попал, R6/R7 показали соседний слот. Для чисел/инстансов использовался rc как сигнал.
- После серии R1–R8 клиент остался жив и стабилен (fires=10, без деградации на этой серии).

## Контрпример стабильности (важно)
На прошлой итерации этой же сборки (pid 52574) после успешного fire+rc=0 клиент умер через ~13 секунд на не связанном на вид вызове (см. crash/). Значит: «rc=0 + жив сразу после» ≠ гарантия отсутствия отложенного повреждения состояния треда.
