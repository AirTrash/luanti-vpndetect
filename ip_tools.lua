--[[
Вспомогательный функции для работы с ip адресами.
]]

local ip_tools = {}


--Проверить валидность ip адреса, записанного в виде строки.
function ip_tools:validate_ipstr(ipstr)
	local nums = string.split(ipstr, ".")
	if #nums ~= 4 then return false end

	for _, octet in pairs(nums) do
		octet = tonumber(octet)
		if type(octet) ~= "number" then return false end
		if octet < 0 or octet > 255 then return false end
	end
	return true
end


--Проверить валидность всех ip адресов, разделенных разделителем(sep).
function ip_tools:parse_ipstrs(ipstrs, sep)
	local ipstrs = string.split(ipstrs, sep)

	if #ipstrs == 0 then return nil end

	for idx, ipstr in pairs(ipstrs) do
		ipstrs[idx] = ipstr:trim()
		if self:validate_ipstr(ipstrs[idx]) == false then
			return nil
		end
	end
	return ipstrs
end



return ip_tools
