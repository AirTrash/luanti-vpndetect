--[[
Работа VPN детектора.
Обработка подключений игроков, проверка ip адреса и применение
соответствующих действий в случае обнаружения VPN
]]


local storage = core.get_mod_storage("vpndetect")
local sql = vpndetect.sql
local policy = vpndetect.policy
local http_api = vpndetect.http_api
local actions = vpndetect.actions

local names_cache = {}


--Применение действий в соответсвии с ip адресом
local function player_processing(player_name, ip_type)
	if ip_type == "whitelist" then
		return
	end
	vpndetect.log("warning", "vpn connection detected, player name: " .. player_name)

	local action = policy:get_option("action_on_detect")
	vpndetect.log("action", string.format("The following action will be performed with respect to the %s player: %s", player_name, action))
	actions[action](player_name)
end


--Парсинг данных при от vpnapi.io
local function parse_data(data)
	if data.ip == nil then
		return nil, "Ip not found in vpnapi response"
	elseif data.security == nil then
		return nil, "Security not found in vpnapi response"
	end

	local sec = data.security
	local ip_table = {ip=data.ip}

	if sec.proxy or sec.relay or sec.vpn or sec.tor then
		ip_table.type = "blacklist"
	else
		ip_table.type = "whitelist"
	end

	return ip_table
end


--Обработка ответа от vpnapi.io
local function response_process(result)
	if result.timeout ~= false then
		vpndetect.log("error", "IP request time has expired, the ip cannot be verified")
		return
	elseif result.code ~= 200 then
		vpndetect.log("error", "IP request not returned code 200, the ip cannot be verified")
		return
	end

	local data = core.parse_json(result.data)
	if data == nil then
		vpndetect.log("error", "Can't parse json, the ip cannot be verified")
		return
	end
	local ip_table, err = parse_data(data)
	if ip_table == nil then vpndetect.log("error", err .. ", the ip cannot be verified"); return end

	vpndetect.log("info", "Detected new ip address " .. ip_table.ip)
	sql:set_ip(ip_table.ip, ip_table.type)

	local name = names_cache[ip_table.ip]
	if name == nil then
		vpndetect.log("error", "couldn't get the name by ip address error in program logic, the ip cannot be verified")
		return
	end
	names_cache[ip_table.ip] = nil

	player_processing(name, ip_table.type)
end


--Запрос к vpnapi.io
local function request_ip(name, ip)
	local key = storage:get_string("vpnapi_key")
	if key == "" then
		vpndetect.log("error", "vpnapi_key option is not established, the ip cannot be verified")
		return
	end
	local request = {
		url=string.format("https://vpnapi.io/api/%s?key=%s", ip, key),
		method="GET",
		timeout=10
	}
	names_cache[ip] = name
	http_api.fetch(request, response_process)
end


--Обработка "подключений" к серверу
core.register_on_joinplayer(function(player)
	if not policy:get_option("detector_enabled") then
		vpndetect.log("warning", "vpn detector disabled, ip will not be verified")
		return
	end
	local name = player:get_player_name()
	local ip = core.get_player_ip(name)
	if ip == nil then return end

	local record = sql:get_ip(ip)
	if record ~= nil then
		player_processing(name, record.type)
		return
	end
	request_ip(name, ip)
end)


--Установить api ключ vpnapi.io
core.register_chatcommand("vdt_set_apikey", {
	params = "<key>",
	privs = {vpndetect_admin=true},
	description = "Set api key for vpnapi.io",
	func = function(name, param)
		storage:set_string("vpnapi_key", param)
		return true, "Success"
	end
})


--Показать установленный ключ vpnapi.io
core.register_chatcommand("vdt_show_apikey", {
	description = "Show seted api key for vpnapi.io",
	privs = {vpndetect_admin=true},
	func = function()
		local key = storage:get_string("vpnapi_key")
		return true, "Key: " .. key
	end
})


--В будущем. Статус работы детектора.
core.register_chatcommand("vdt_status", {
	description = "Show vpndetector status",
	privs = {vpndetect_admin=true},
	func = function()

	end
})