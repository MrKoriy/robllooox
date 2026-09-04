# Руководство по обновлению сигнатур и оффсетов Roblox (macOS ARM64)

Документ описывает процедуру обновления сигнатур и оффсетов `executor-core` при выходе новых версий клиента Roblox на macOS.

---

## 1. Определение текущей версии клиента

Каждая версия Roblox имеет уникальный идентификатор версии (версию GUID).

```bash
# Получить версию установленного клиента Roblox
/Applications/Roblox.app/Contents/MacOS/RobloxPlayer --version 2>&1
```

Текущая версия на момент сборки: `0.732.0.7321040`

---

## 2. Поиск RTTI символов и структуры классов

Хотя бинарник Roblox избавлен от стандартных имен функций C++, имена C++ классов, vtable и RTTI типов сохраняются в секциях `__cstring` и `__const`.

```bash
# Поиск RTTI для ScriptContext, TaskScheduler и ExtraSpace
python3 tools/find_offsets.py
```

Ключевые классы RTTI:
* `RBX::ScriptContext`
* `RBX::TaskScheduler`
* `RBX::ScriptContextFacets::ExecutorFacet`
* `RobloxExtraSpace::Shared`

---

## 3. Снятие защиты Hardened Runtime при обновлении

При обновлении Roblox бинарник переписывается заново. Перед инъекцией необходимо повторно применить **ad-hoc подпись**:

```bash
# Снять Hardened Runtime подпись и установить ad-hoc
codesign -s - -f /Applications/Roblox.app/Contents/MacOS/RobloxPlayer
```

Проверить статус подписи:
```bash
codesign -dvv /Applications/Roblox.app/Contents/MacOS/RobloxPlayer
# Ожидаемый вывод: Signature=adhoc, flags=0x2(adhoc)
```

---

## 4. Структура Luau ExtraSpace & Identity

Код безопасности Luau в Roblox использует заголовок `RobloxExtraSpace` перед `lua_State`:

```cpp
struct RobloxExtraSpace {
    struct Shared {
        int script_context;
        uint64_t capabilities; // Маска разрешений (0x3FFFFFF)
        int identity;          // Идентификатор потока (7 = Executor)
    } *shared;
    int identity;
    uint64_t capabilities;
};
```

Повышение прав до уровня исполнителя выполняет функция:
```cpp
executor_set_identity(L, 7, 0x3FFFFFFULL);
```
