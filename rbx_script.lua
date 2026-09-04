-- rbx_script.lua
-- Тестовый скрипт для выполнения в инжектированной среде через сокет или локальный файл

local function main()
    print("[INJ Lua] Executing in host environment...")
    
    -- Пример проверки стандартных глобалов
    if _VERSION then
        print("[INJ Lua] Lua Version: " .. tostring(_VERSION))
    end
    
    -- Пример взаимодействия с Roblox API (если доступен)
    if game and type(game.GetService) == "function" then
        local players = game:GetService("Players")
        local localPlayer = players.LocalPlayer
        print("[INJ Lua] Roblox Game detected! LocalPlayer: " .. (localPlayer and localPlayer.Name or "None"))
    else
        print("[INJ Lua] Standard Lua environment active.")
    end
end

local success, err = pcall(main)
if not success then
    print("[INJ Lua Error] " .. tostring(err))
end
