local storage = core.get_mod_storage("vpndetect")
local modpath = core.get_modpath("vpndetect")
local sql = vpndetect.sql
local policy = vpndetect.policy
local actions = vpndetect.actions

local format_table = dofile(modpath .. "/table_formatter.lua")


local function num_validator(param)
	param = tonumber(param)
	if param ~= nil then
		return param
	end
	return nil, "Parameter should be a number!!!"
end


local function bool_validator(value)
	if value ~= "true" and value ~= "false" then
		return nil, "Value can only be true or false"
	end
	return value
end


local function action_validator(value)
	if actions[value] then
		return value
	else
		local msg = "Invalid action, possible actions: "
		for val, _ in pairs(actions) do
			msg = msg .. val .. " "
		end
		return nil, msg
	end
end


local options = {
	whitelist_max_age = {
		type = "number",
		description = "Max age for records in days",
		validator = num_validator,
		default = 10,
		help = [[
In order not to take up a lot of space, records from the white and black list will be deleted,
this number is responsible for how many days the records will be stored.
]]
	},
	blacklist_max_age = {
		type = "number",
		description = "Max age for records in days",
		validator = num_validator,
		default = 30,
		help = [[
In order not to take up a lot of space, records from the white and black list will be deleted,
this number is responsible for how many days the records will be stored.
]]
	},
	detector_enabled = {
		type = "bool",
		description = "Enable vpndetect, could be true or false",
		validator = bool_validator,
		default = "true"
	},
	autoclear_enabled = {
		type = "bool",
		description = "Enable automatic daily cleaning of old records, could be true or false",
		validator = bool_validator,
		default = "true"
	},
	action_on_detect = {
		type = "string",
		description = "Action if vpn detected",
		validator = action_validator,
		default = "kick",
		help = [[
The action that will be performed if a VPN connection is detected:
    kick - disconnect player
]]
	}
}


local option_getters = {
	["number"] = function(id)
		local val = storage:get_int(id)
		if val == 0 then return nil end
		return val
	end,
	["string"] = function(id)
		local val = storage:get_string(id)
		if val == "" then return nil end
		return val
	end,
	bool = function(id)
		local val = storage:get_string(id)
		if val == "" then return nil end
		if val == "false" then return false end
		if val == "true" then return true end
	end
}


local option_setters = {
	["number"] = function(id, value)
		storage:set_int(id, value)
    end,
	["string"] = function(id, value)
		storage:set_string(id, value)
	end,
	bool = function(id, value)
		if value ~= "true" and value ~= "false" then
			error("value can only be 'false' or 'true'")
		end
		storage:set_string(id, value)
	end
}


local function init_options()
	vpndetect.log("info", "Policy manager initializing options...")
	for id, option in pairs(options) do
		local value = option_getters[option.type](id)
		if value == nil then
			if option.default == nil then
				vpndetect.log("warning", "Option " .. id .. " not seted, and default value is absent!")
			else
				option_setters[option.type](id, option.default)
				vpndetect.log("info", "Option " .. id .. " not set, using default: " .. tostring(option.default))
			end
		else
			vpndetect.log("info", "Option " .. id .. " = " .. tostring(value))
		end
	end
end


init_options()


function policy:set_option(option_id, value)
	local opt = options[option_id]
	if not opt then return false, "Option " .. option_id .. " does not exist" end

	local validated, err = opt.validator(value)
	if not validated then return false, err end

	option_setters[opt.type](option_id, validated)
	return true
end


function policy:get_option(option_id)
	local opt = options[option_id]
	if not opt then return nil, "Option " .. option_id .. " does not exist" end
	return option_getters[opt.type](option_id)
end


core.register_chatcommand("vdt_policy_set", {
	params = "<option_id> <value>",
	privs = {vpndetect_admin=true},
	description = "Sets a variable to a value",
	func = function(name, param)
		local params = string.split(param, " ", false, 2)
		local res, err = policy:set_option(params[1], params[2])
		if res then
			return true, "Success"
		end
		return true, err
	end
})


core.register_chatcommand("vdt_policy_options", {
	description = "Show current policy options",
	privs = {vpndetect_admin=true},
	func = function(name, param)
		local msg = {{"OPTION", "VALUE","TYPE", "DESCRIPTION"}}
		for id, option in pairs(options) do
			local value = tostring(policy:get_option(id))
			if value == "nil" then value = "not seted" end

			table.insert(msg, {id, value, option.type, option.description})
		end
		return true, format_table(msg, " | ")
	end
})


core.register_chatcommand("vdt_policy_help", {
	params = "<option_id>",
	privs = {vpndetect_admin=true},
	description = "Show help list for option",
	func = function(name, param)
		local opt = options[param]
		if opt == nil then return true, "Option " .. param .. " not exists" end
		return true, opt.help or opt.description
	end
})
