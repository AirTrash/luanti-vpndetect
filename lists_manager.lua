--[[
Работа со списками ip адресов.
Добавление в список, удаление, вывод списка, очистка старых записей (ручная/автоматическая).
]]

local storage = core.get_mod_storage()
local worldpath = core.get_worldpath()
local modpath = core.get_modpath("vpndetect")
local policy = vpndetect.policy

local ip_tools = dofile(modpath .. "/ip_tools.lua")

local sql = vpndetect.sql


--Получить ip адреса в виде строки
local function get_ips(type_)
	local list
	local values
	if type_ == "blacklist" then
		list = "Black list:\n"
		values = sql:get_black_list()
	elseif type_ == "whitelist" then
		list = "White list:\n"
		values = sql:get_white_list()
	else
		error(type_ .. "is not supported, please use blacklist or whitelist")
	end

	for _, val in pairs(values) do
		list = list .. "  " .. val[1] .. " created: " .. os.date("%Y-%m-%d %H-%M-%S", val[2]) .. "\n"
	end
	list = list .. "Count: " .. tostring(#values)
	return list
end


--Установить ip адрес(а) в "белый" или "черный" список.
local function set_ips_type(ips, type_)
	local ips = ip_tools:parse_ipstrs(ips, ",")

	if ips == nil then return "Incorrect arguments" end
	local res, err = sql:set_ips(ips, type_)
	
	if res then
		return "Success"
	else
		return "Error: " .. err
	end
end


--Очистить устаревшие записи из БД
function clear_old_records()
	local white_age = storage:get_int("whitelist_max_age")
	local black_age = storage:get_int("blacklist_max_age")
		
	local now = os.time()
	local white_cutoff = now - (white_age * 86400)
	local black_cutoff = now - (black_age * 86400)
	local count, err = sql:clear_old_records(white_cutoff, black_cutoff)

	if not count then
		return false, "Failed delete old records: " .. err
	end
	return true, "Deleted " .. count .. " old records"
end


--Показать черный список.
core.register_chatcommand("vdt_blacklist", {
	description = "Show first 50 black list records",
	privs = {vpndetect_admin=true},
	func = function (name, param)
		return true, get_ips("blacklist")
	end
})


--Показать белый список.
core.register_chatcommand("vdt_whitelist", {
	description = "Show first 50 white list records",
	privs = {vpndetect_admin=true},
	func = function (name, param)
		return true, get_ips("whitelist")
	end
})


--Установить ip адрес(а) в белый список.
core.register_chatcommand("vdt_set_ip_white", {
	params = "<ip_addresses>",
	privs = {vpndetect_admin=true},
	description = "Set ip addresses as white\n<ip_addresses> - IP addresses shared by commas",
	func = function(name, param)
		return true, set_ips_type(param, "whitelist")
	end
})


--Установить ip адрес(а) в черный список.
core.register_chatcommand("vdt_set_ip_black", {
	params = "<ip_addresses>",
	privs = {vpndetect_admin=true},
	description = "Set ip addresses as black\n<ip_addresses> - IP addresses shared by commas",
	func = function(name, param)
		return true, set_ips_type(param, "blacklist")
	end
})


--Удалить ip адрес из БД.
core.register_chatcommand("vdt_del_ip", {
	params = "<ip_addresses>",
	privs = {vpndetect_admin=true},
	description = "Set ip addresses as white\n<ip_addresses> - IP addresses shared by commas",
	func = function(name, param)
		local ips = ip_tools:parse_ipstrs(param, ",")
		if ips == nil then return true, "Incorrect arguments" end

		local res, err = sql:del_ips(ips)

		if res then
			return true, "Success"
		else
			return true, "Error: " .. err
		end
	end
})


--Ручная очистка устаревших записей из БД.
core.register_chatcommand("vdt_clear_old_records", {
	description = "Run the process of cleaning old records manually",
	privs = {vpndetect_admin=true},
	func = function(name, param)
		local _, msg = clear_old_records()
		return true, msg
	end
})


--Запланировать автоматическую очистку.
local function schedule_clean()
	local last_time = storage:get_int("last_clear_time")
	local current_time = os.time()
	local diff_time = current_time - last_time
	local delay = math.max(0, 86400 - diff_time)

	core.after(delay, function()
		storage:set_int("last_clear_time", os.time())
		if policy:get_option("autoclear_enabled") then
			local _, msg = clear_old_records()
			vpndetect.log("action", "clear old records: " .. msg)
		else
			vpndetect.log("info", "autoclear disabled, old records will not be cleared.")
		end
		schedule_clean()
	end)
end


schedule_clean()
