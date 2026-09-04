-- hello.lua — минимальная проверка IPC и Lua-состояния
print("Привет из инжектированного процесса!")
print("Lua: " .. tostring(_VERSION))
return "возвращаемое значение", 2 + 2
