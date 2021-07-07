local json = require "cjson"
local http = require "resty.http"
local base64 = require "ngx.base64"

ngx.req.read_body()
local code = json.decode(ngx.req.get_body_data()).code

if not code then
    return ngx.exit(400)
end

local qs = "appid=wxf2f778868fd916f6&secret=92ed93f90bba06458377f75c6843d716&grant_type=authorization_code&js_code="..code
local httpc = http.new()
local wxres, wxerr = httpc:request_uri("https://api.weixin.qq.com/sns/jscode2session?"..qs, {
    ssl_verify = false,
    method = "GET"
})

if not wxres then
    ngx.log(ngx.ERR, "wx request error:", wxerr)
    return ngx.exit(500)
end

local openid = json.decode(wxres.body).openid
ngx.header.content_type = "application/json;charset=utf-8"

if not openid then
    ngx.status = 400
    return ngx.say(wxres.body)
end

local uname = openid.."@hyc.com"
local upass = base64.encode_base64url(uname)

local res, err = httpc:request_uri("http://172.16.0.4:8080/auth/realms/hyc/protocol/openid-connect/token", {
    method = "POST",
    body = "client_id=hyc-wmp-console&grant_type=password&username="..uname.."&password="..upass,
    headers = {
    ["Content-Type"] = "application/x-www-form-urlencoded",
  },
})

if res.status == 200 then
    ngx.status = res.status
    ngx.say(res.body)
else
    local bindingres = {
        binding = upass
    }
    ngx.status = 400
    ngx.say(json.encode(bindingres))
end
