# environment.md — точная исходная точка

## Репозиторий и исходная точка
- Репо: `https://github.com/MrKoriy/robllooox.git`
- Ветка: `main`
- HEAD commit: `d49d5ed4e3a2ad3ad9af9620c5efc90b89d9597c`
  («hijack coroutine code complete … pcall-hook plan», 2026-10-06 17:36:26 +0300)
- Синхронизация с origin: `ahead 0, behind 0` — опубликованная версия == локальный HEAD.
- **Незакоммиченные изменения** (рабочее дерево — фактическая тестируемая сборка):
  - `executor_core.cpp` — +новый deferred-exec механизм (pcall-hook): `__ARM__/__POLL__/__REARM__/__DISARM__/__ARMG__`, fixed-frame trampoline, stale-hook recovery, VM_PROT_COPY fallback, полный save/restore фрейма (ci/base_ci/base/top), фикс remove_segv_guard (перепутанные SEGV/BUS);
  - `executor_core.h` — прототипы arm-API;
  - `payload.c` — IPC-команды __ARM__/__POLL__/__REARM__/__DISARM__/__ARMG__;
  - `FINDINGS.md` — запись сессии ФИНАЛ-6;
  - untracked: `tools/run741.py` (компиляция+wire-ремап+IPC), `tools/wiremap741.py` (вывод wire-карты), `tools/fly741.py` (флай-драйвер).
  - Полный diff: `logs/uncommitted.diff` (921 строка).

## Хост
- macOS 27.2 (build 26B5091g), arm64 (Apple M3 Pro, 18 GB).
- Xcode 27.0 (27A266a); clang Apple 21.0.0 (clang-2100.3.34.2), target arm64-apple-darwin27.2.0.
- Python 3.14.7 (Homebrew, /opt/homebrew).
- Luau (внешний компилятор для wire-чанков): /tmp/luau-src @ 421cc81 («Hash TypeId… #3007»), собран как `luau-compile --fflags=false --binary` (LBC v9 target).

## Клиент Roblox
- Версия: **0.741.0.7411056** (CFBundleVersion 7411056).
- Бинарь: `/Applications/Roblox.app/Contents/MacOS/RobloxPlayer`, Mach-O arm64 (magic cffaedfe — НЕ arm64e-срез: PAC-сигнатур в прологах нет).
- Mach-O UUID: **1807A3EA-4BD2-3B5C-9F4A-E002284A876A** (arm64).
- Клиент предварительно adhoc-реподписан (tools/resign_adhoc.sh; бэкап `~/roblox_backups/RobloxPlayer.orig-741`).

## Сборка и запуск
- Сборка: `make` (= `clang -Wall -Wextra -O2 -fPIC` + `clang++ -std=c++17`, universal `-arch arm64 -arch x86_64`, link `-dynamiclib -undefined dynamic_lookup -lc++`, затем `codesign -s - --force payload.dylib`).
- Тестируемый артефакт: `payload.dylib`, **SHA-256: `73d2356171bb2a5f007f990e7c6381534d5bb30c0b1f4f8d2df198f1d3ddf6d4`**.
- Запуск: `./live_inject.sh` (lldb `dlopen` свежей копии `/tmp/inj_payload_<ts>.dylib` в живой процесс; DYLD_INSERT на этом билде не работает — см. FINDINGS).
- Джойн: `open "roblox://experiences/start?placeId=1818"`.
- IPC: unix-socket `/tmp/inj_ipc_501.sock` (chmod 0600).

## Соответствие локального кода репозиторию
- origin/main == HEAD; вся живая работа — незакоммиченный diff + untracked tools. Ничего не смешано: в сессии 2026-10-06/07 использована именно эта сборка (sha256 выше).
- ВНИМАНИЕ: в течение сессии в один и тот же процесс загружалось несколько копий dylib (live_inject копирует под новым именем специально); до исправления stale-hook recovery это привело к одному фатальному кейсу «сложенные патчи» (см. crash-анализ).

## Что есть в процессе на момент сбора (live state)
- Процесс RobloxPlayer pid 52574, в игре (placeId 1818, «Game join succeeded» в логе).
- Загружен payload со всеми правками diff'а; на luaB_pcall (0x1026dde64+slide) установлен wide-патч (16 байт) → trampoline в `__TEXT,__hookpad`.
