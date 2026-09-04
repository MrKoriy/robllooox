-- roblox_probe.lua — проверка доступности Roblox API из Lua-состояния payload'а
-- Примечание: payload создаёт СОБСТВЕННОЕ Lua-состояние, а не состояние игры.
-- Глобалы Roblox (game, workspace и т.п.) будут доступны, только если
-- символы разрешены из процесса игры и состояние общее.

if game and type(game.GetService) == "function" then
  print("[+] Обнаружено Roblox-окружение!")
  local players = game:GetService("Players")
  local lp = players and players.LocalPlayer
  print("LocalPlayer: " .. (lp and lp.Name or "нет"))
else
  print("[i] Глобал 'game' недоступен — это отдельное Lua-состояние payload'а.")
  print("[i] Доступны только стандартные библиотеки Lua.")
end
