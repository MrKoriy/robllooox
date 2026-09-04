-- env_info.lua — информация об окружении Lua внутри целевого процесса
print("=== Lua environment ===")
print("_VERSION: " .. tostring(_VERSION))

local function has(name) return rawget(_G, name) ~= nil end
for _, g in ipairs({"os", "io", "string", "table", "math", "coroutine", "debug", "utf8"}) do
  print(string.format("lib %-10s %s", g, has(g) and "OK" or "—"))
end

if os and os.time then
  print("os.time:  " .. os.time())
end
if os and os.getenv then
  print("USER:     " .. tostring(os.getenv("USER")))
end
