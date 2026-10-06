local ws = game.Workspace
local cam = ws.CurrentCamera
local lv = cam.CFrame.LookVector
local root = ws:FindFirstChild(game.Players.LocalPlayer.Name).HumanoidRootPart
root.AssemblyLinearVelocity = Vector3.new(lv.X*60, lv.Y*60, lv.Z*60)
