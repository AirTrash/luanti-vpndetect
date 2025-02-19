--[[
Работа с базой данных
]]

local modpath = core.get_modpath("vpndetect")

if not vpndetect.ie then
	error("Cannot access insecure environment! Please add vpndetect to trusted mods!")
end

local sqlite3 = vpndetect.ie.require("lsqlite3")
local db_path = modpath .. "/vpndetect.db"

local db = sqlite3.open(db_path)
if not db then error("Can't open " .. db_path) end

--Создать таблицу, если ее не существует.
db:exec[[
	CREATE TABLE IF NOT EXISTS ip_addresses (
		ip TEXT PRIMARY KEY,
		type TEXT NOT NULL,
		created INTEGER DEFAULT (strftime('%s', 'now'))
	)
]]

--Отключиться от БД при выключении сервера.
minetest.register_on_shutdown(function()
	if db then
		db:close()
	end
end)


--Вставка ip адресов.
local stmt_insert = db:prepare[[
INSERT OR REPLACE INTO ip_addresses (ip, type) VALUES (?, ?)
]]

--Удаление конкретного ip адреса.
local stmt_delete = db:prepare[[DELETE FROM ip_addresses WHERE ip = ?]]

--Получение ip адресов из белого списка.
local stmt_select_white = db:prepare[[
SELECT ip, created FROM ip_addresses WHERE type = 'whitelist' LIMIT 50]]

--Получение ip адресов из черного списка.
local stmt_select_black = db:prepare[[
SELECT ip, created FROM ip_addresses WHERE type = 'blacklist' LIMIT 50]]

--Получение конкретного ip адреса.
local stmt_select_ip = db:prepare[[
SELECT ip, type FROM ip_addresses WHERE ip = ?]]


--Посчитать колличество записей в БД.
local stmt_count = db:prepare("SELECT COUNT(*) FROM ip_addresses WHERE type = ?")

--Удалить устаревшие записи.
local stmt_clear = db:prepare[[
DELETE FROM ip_addresses WHERE (type = 'whitelist' AND created < ?) OR (type = 'blacklist' AND created < ?)]]


--Установить ip адреса в белый или черный список.
function vpndetect.sql:set_ips(ips, type_)
	if type_ ~= "blacklist" and type_ ~= "whitelist" then
		error(type_ .. " is not supported, please use whitelist or blacklist")
	end

	db:exec("BEGIN")
	for _, ip in pairs(ips) do
		stmt_insert:reset()
		stmt_insert:bind_values(ip, type_)

		local res = stmt_insert:step()
		if res ~= sqlite3.DONE then
			local err = db:errmsg()
			db:exec("ROLLBACK")
			vpndetect.log("error", "Failed to execute query: " .. err)
			return false, err
		end
	end
	db:exec("COMMIT")
	return true
end


--Установить ip адрес в белый или черный список.
function vpndetect.sql:set_ip(ip, type_)
	if type_ ~= "blacklist" and type_ ~= "whitelist" then
		error(type_ .. " is not supported, please use whitelist or blacklist")
	end
	stmt_insert:reset()
	stmt_insert:bind_values(ip, type_)

	local res = stmt_insert:step()
	if res ~= sqlite3.DONE then
		local err = db:errmsg()
		vpndetect.log("error", "Failed to execute query: " .. err)
		return false, err
	end
	return true
end


--Удалить старые записи.
--Принимает крайние даты в виде timestamp.
function vpndetect.sql:clear_old_records(white_threshold, black_threshold)
	stmt_clear:reset()
	stmt_clear:bind_values(white_threshold, black_threshold)
	local res = stmt_clear:step()
	if res ~= sqlite3.DONE then
		local err = db:errmsg()
		vpndetect.log("error", "Failed to execute query: " .. err)
		return nil, err
	end
	return db:changes()
end


--Удалить ip адреса.
--Принимает список ip адресов в виде строки.
function vpndetect.sql:del_ips(ips)
	db:exec("BEGIN")
	for _, ip in pairs(ips) do
		stmt_delete:reset()
		stmt_delete:bind_values(ip)

		local res = stmt_delete:step()
		if res ~= sqlite3.DONE then
			local err = db:errmsg()
			db:exec("ROLLBACK")
			vpndetect.log("error", "Failed to execute query: " .. err)
			return false, err
		end
	end
	db:exec("COMMIT")
	return true
end


--Выполнить select выражение
local function select_exec(stmt)
	stmt:reset()
	local ret = {}
	while stmt:step() == sqlite3.ROW do
		local values = stmt:get_values()
		table.insert(ret, values)
	end
	return ret
end


--Получить список ip адресов белого списка.
function vpndetect.sql:get_white_list()
	return select_exec(stmt_select_white)
end


--Получить список ip адресов черного списка.
function vpndetect.sql:get_black_list()
	return select_exec(stmt_select_black)
end


--Получить конкретный ip адрес.
function vpndetect.sql:get_ip(ip)
	stmt_select_ip:reset()
	stmt_select_ip:bind_values(ip)
	local res = stmt_select_ip:step()
	if res == sqlite3.ERROR then
		vpndetect.log("error", "Failed to execute query: " .. db:errmsg())
		return nil
	end
	if res ~= sqlite3.ROW then return nil end

	local values = stmt_select_ip:get_values()
	return {ip = values[1], type = values[2]}
end


--Посчитать кол-во записей в БД.
function vpndetect.sql:count_ips(type_)
	if type_ ~= "blacklist" and type_ ~= "whitelist" then
		error("type can be only 'blacklist' or 'whitelist'")
	end
	stmt_count:reset()
	stmt_count:bind(1, type_)
	if stmt_count:step() == sqlite3.ROW then
		local count = stmt_count:get_value(0)
		return count
	end
	local err = db:errmsg()
	vpndetect.log("error", "Failed to execute query: " .. err)
	return nil, err
end
