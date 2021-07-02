local json = require "cjson"
local http = require "resty.http"
local base64 = require "ngx.base64"

local hyc_role_mapping = {
        hycr_operator = {"/process/project/", "/process/order/", "/process/workorder/", "/process/detail/", "/process/reply/", "/drawing/detailWithProc/", "/drawing/queryByPage", "/deploy/"}, 
        hycr_programmer = {"/program/", "/drawing/query", "/drawing/detail", "/process/queryMyProcess", "/process/detail/", "/process/getVersions/", "/process/save", "/dict/"}, 
        hycr_auditor = {"/process/queryByPage", "/drawing/queryByPage", "/process/detail/", "/drawing/detailWithProc/", "/drawing/detail/", "/process/audit", "/distribute/"}, 
        hycr_deployer = {"/deploy/", "/drawing/detailWithProc/", "/drawing/queryByPage", "/process/detail/"}, 
        hycr_producer = {"/process/workorder/", "/drawing/detailWithProc/", "/process/detail/", "/process/update/", "/process/order/"}, 
        hycr_planner = {"/process/project/", "/process/reply/", "/process/workorder/", "/drawing/detailWithProc/", "/process/order/", "/process/detail/"}
        }
local hycex_role_mapping = {
        hycr_operator = {"/process/order/", "/drawing/detailWithProc/", "/process/detail/", "/deploy/query"}, 
        hycr_programmer = {"/drawing/query", "/drawing/detailWithProc/", "/process/detail/", "/drawing/detail/", "/process/queryMyProcess", "/program/", "/process/getVersions/", "/process/save", "/dict/"}, 
        hycr_deployer = {"/deploy/", "/drawing/detailWithProc/", "/process/detail/"}, 
        hycr_producer = {"/process/order/", "/drawing/detailWithProc/", "/process/detail/", "/process/update/", "/deploy/query"}
        }
local hyc_uri_black_section = {"/process/", "/drawing/", "/deploy/", "/program/", "/distribute/", "/dict/"}

function is_inblack(uri, tab)
    for i, v in ipairs(tab) do
        if (string.find(uri, v) ~= nil) then
            return true
        end
    end
    return false
end

function get_identity(jwt)
    local sep = "."
    local t={}
    for sec in string.gmatch(jwt, "([^"..sep.."]+)") do
        table.insert(t, sec)
    end
    return json.decode(base64.decode_base64url(t[2]))
end

function is_authorized(identity, uri)
    local mapping = hyc_role_mapping
    if (string.find(identity.groups[1], "hycgex") ~= nil) then
        mapping = hycex_role_mapping
    end

    for i, v in ipairs(identity.realm_access.roles) do
        for m, n in ipairs(mapping[v]) do
            if (string.find(uri, n) ~= nil) then
                return ture
            end
        end
    end
    return false
end

local uri = ngx.var.uri

if (is_inblack(uri, hyc_uri_black_section) == false) then
    return
end

local token = ngx.var.http_Authorization

if (not token) or (token == null) or (token == ngx.null) then
    return ngx.exit(401)
end
    
local httpc = http.new()
local res, err = httpc:request_uri("http://{HOST}:{PORT}/auth/realms/hyc/protocol/openid-connect/userinfo", {
    method = "GET",
    headers = {
        ["Authorization"] = token,
    }
})

if (res.status ~= 200) then
    return ngx.exit(401)
end

local identity = get_identity(token)

if (is_authorized(identity, uri) == false) then
    return ngx.exit(403)
end

return
