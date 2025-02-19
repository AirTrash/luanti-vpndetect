local modpath = core.get_modpath("vpndetect")

if not vpndetect.ie then
	error("Cannot access insecure environment! Please add vpndetect to trusted mods!")
end

local sqlite3 = vpndetect.ie.require("lsqlite3")
local db_path = modpath .. "/vpndetect.db"

local db = sqlite3.open(db_path)
if not db then error("Can't open " .. db_path) end

db:exec[[
	CREATE TABLE IF NOT EXISTS ip_addresses (
		ip TEXT PRIMARY KEY,
		type TEXT NOT NULL,
		created INTEGER DEFAULT (strftime('%s', 'now'))
	)
]]

minetest.register_on_shutdown(function()
	if db then
		db:close()
	end
end)


local stmt_insert = db:prepare("INSERT OR REPLACE INTO ip_addresses (ip, type) VALUES (?, ?)")
local stmt_delete = db:prepare("DELETE FROM ip_addresses WHERE ip = ?")
local stmt_select_white, err = db:prepare("SELECT ip, created FROM ip_addresses WHERE type = 'whitelist' LIMIT 50")
local stmt_select_black = db:prepare("SELECT ip, created FROM ip_addresses WHERE type = 'blacklist' LIMIT 50")
local stmt_select_ip = db:prepare("SELECT ip, type FROM ip_addresses WHERE ip = ?")


local stmt_clear = db:prepare("DELETE FROM ip_addresses WHERE (type = 'whitelist' AND created < ?) OR (type = 'blacklist' AND created < ?)")


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


local function select_exec(stmt, getter)
	stmt:reset()
	local ret = {}
	while stmt:step() == sqlite3.ROW do
		local values = stmt:get_values()
		table.insert(ret, values)
	end
	return ret
end


function vpndetect.sql:get_white_list()
	return select_exec(stmt_select_white)
end


function vpndetect.sql:get_black_list()
	return select_exec(stmt_select_black)
end


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
