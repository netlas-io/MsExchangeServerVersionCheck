local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local strbuf = require "strbuf"

description = [[
Check for Exchange Server Version 
]]

---
--@output
-- PORT    STATE SERVICE
-- 443/tcp open  https
-- |_nse_detect: OWA:15.2.858  Exchange:15.2.858.12

author = "Aleksandr Minin"
license = "GPLv3"
categories = {"default", "discovery", "safe"}

portrule = shortport.http

local last_len = 0

function split(source, delimiters)
    local elements = {}
    local pattern = '([^'..delimiters..']+)'
    string.gsub(source, pattern, function(value) elements[#elements + 1] =     value;  end);
    return elements
end

local function parse_answer_owa(body)
  local found = false
  for line in body:gmatch("[^\r\n]+") do
    for w in line:gmatch('/owa/%d+.%d.%d+') do
      w = string.gsub(w,"/owa/","")
      found = true
          return w
    end
    for w in line:gmatch('/owa/auth/%d+.%d.%d+') do
      w = string.gsub(w,"/owa/auth/","")
      found = true
          return w
    end

  end
  if found == false then
         return "no owa version found"
  end
end

local function parse_answer_ecp(body)
  local found = false
  for line in body:gmatch("[^\r\n]+") do
    for w in line:gmatch('assemblyIdentity.*version="%d+.%d.%d+.%d.') do
      w = string.gsub(w,"assemblyIdentity.*version=\"","")
      found = true
          return w
    end

  end
  if found == false then
         return "no Exchange version found"
  end
end


local function brute_2013_exchange(host, port, version, options)
        if version:find("^15.0.1497") ~= nil then
            versionCheck = {"15.0.1497.18",
                "15.0.1497.15",
                "15.0.1497.12",
                "15.0.1497.1",
                "15.0.1497.8",
                "15.0.1497.7",
                "15.0.1497.6",
                "15.0.1497.4",
                "15.0.1497.3",
                "15.0.1497.2"}
        
        elseif version:find("^15.0.1473") ~= nil then
            versionCheck = {"15.0.1473.6",
                "15.0.1473.5",
                "15.0.1473.4",
                "15.0.1473.3"}
        
        elseif version:find("^15.0.1395") ~= nil then
            versionCheck = {"15.0.1395.12",
                "15.0.1395.10",
                "15.0.1395.8",
                "15.0.1395.7",
                "15.0.1395.4"}
        
        elseif version:find("^15.0.1367") ~= nil then
            versionCheck = {"15.0.1367.9",
                "15.0.1367.6",
                "15.0.1367.3"}
        
        elseif version:find("^15.0.1365") ~= nil then
            versionCheck = {"15.0.1365.7",
                "15.0.1365.001"}
        
        elseif version:find("^15.0.1347") ~= nil then
            versionCheck = {"15.0.1347.3",
                "15.0.1347.2"}
        
        elseif version:find("^15.0.1320") ~= nil then
            versionCheck = {"15.0.1320.7",
                "15.0.1320.6",
                "15.0.1320.4"}
        
        elseif version:find("^15.0.1293") ~= nil then
            versionCheck = {"15.0.1293.6",
                "15.0.1293.4",
                "15.0.1293.2"}
        
        elseif version:find("^15.0.1263") ~= nil then
            versionCheck = {"15.0.1263.5"}
        
        elseif version:find("^15.0.1263") ~= nil then
            versionCheck = {"15.0.1236.6",
                "15.0.1236.3"}
        
        elseif version:find("^15.0.1210") ~= nil then
            versionCheck = {"15.0.1210.6",
                "15.0.1210.3"}
        
        elseif version:find("^15.0.1178") ~= nil then
            versionCheck = {"15.0.1178.9",
                "15.0.1178.6",
                "15.0.1178.4"}
        
        elseif version:find("^15.0.1156") ~= nil then
            versionCheck = {"15.0.1156.10",
                "15.0.1156.6"}
        

        elseif version:find("^15.0.1130") ~= nil then
            versionCheck = {"15.0.1130.7"}
        
        elseif version:find("^15.0.1104") ~= nil then
            versionCheck = {"15.0.1104.5"}
        
        elseif version:find("^15.0.1076") ~= nil then
            versionCheck = {"15.0.1076.9"}
        
        elseif version:find("^15.0.1044") ~= nil then
            versionCheck = {"15.0.1044.25"}
        
        elseif version:find("^15.0.995") ~= nil then
            versionCheck = {"15.0.995.29"}
        
        elseif version:find("^15.0.913") ~= nil then
            versionCheck = {"15.0.913.22"}
        
        elseif version:find("^15.0.847") ~= nil then
            versionCheck = {"15.0.847.64",
                "15.0.847.62",
                "15.0.847.57",
                "15.0.847.55",
                "15.0.847.53",
                "15.0.847.50",
                "15.0.847.47"}
        
        else
            versionCheck = {"2013"}
        end
    for i,w in pairs(versionCheck) do
        url = "/ecp/" .. w .. "/exporttool/microsoft.exchange.ediscovery.exporttool.application"
        local answer = http.get(host, port, url, options )
        if answer.status == 200 then
            -- ver = parse_answer_ecp(answer.body)
            return w 
        end

    end
    return url
end


action = function(host, port)
  local dis_count, noun
  options = {header={}}    options['header']['User-Agent'] = "Mozilla/5.0 (Exchange version detect)"
  local answer = http.get(host, port, "/owa", options )

  if answer.status == 302 then
    output =  "Error 302 " .. answer.location
  elseif answer.status ~= 200 then
    output =  "Error " .. tostring(answer.status) .. " for /owa"
  end

  local v_level = nmap.verbosity() + (nmap.debugging()*2)
  local output = strbuf.new()
  local detail = 15

  output = parse_answer_owa(answer.body)
  output2 = "not found"
  if output:find("^15.0.*") ~= nil then
    -- start brute
    output2 = brute_2013_exchange(host, port, output,options)
    
  else
    local answer_ecp = http.get(host, port, "/ecp/Current/exporttool/microsoft.exchange.ediscovery.exporttool.application", options )
    if answer_ecp.status == 200 then
        output2 = parse_answer_ecp(answer_ecp.body)
    end
  end

  return "OWA:" .. output .. "  Exchange:" .. output2 
end