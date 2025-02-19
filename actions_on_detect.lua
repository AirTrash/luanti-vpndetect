--[[
Действия при обнаружении подключения с VPN
]]


local actions = vpndetect.actions


--Кикнуть игрока
actions.kick = function (player_name)
	if core.get_player_by_name(player_name) == nil then
		return
	end
	core.kick_player(player_name, "A VPN has been detected, if this is an error, please contact the server administration to add your address to the whitelist.")
end
