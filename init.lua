local modpath = core.get_modpath("vpndetect")
local http_api = core.request_http_api()


if http_api == nil then
	error("It was not possible to get HttpApiTable, please add a mod to trusted mods and check if the server with Curl support is compiled")
end

core.register_privilege("vpndetect_admin", {
	description = "vpndetect administration",
	give_to_singleplayer = false,
	give_to_admin = false
})

vpndetect = {}
vpndetect.log = function(mode, msg) core.log(mode, "[vpndetect] " .. msg) end
vpndetect.sql = {}
vpndetect.policy = {}
vpndetect.actions = {}

vpndetect.ie = core.request_insecure_environment()
vpndetect.http_api = http_api

dofile(modpath .. "/lists_manager.lua")
dofile(modpath .. "/actions_on_detect.lua")
dofile(modpath .. "/policy_manager.lua")
dofile(modpath .. "/detector.lua")
dofile(modpath .. "/sql.lua")
