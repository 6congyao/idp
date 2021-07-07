local json = require "cjson"
local http = require "resty.http"
local base64 = require "ngx.base64"

ngx.req.read_body()
local args = ngx.req.get_post_args()

if not args then
    return ngx.exit(400)
end

ngx.header.content_type = "application/json;charset=utf-8"
local httpc = http.new()

local res, err = httpc:request_uri("http://172.16.0.4:8080/auth/realms/hyc/protocol/openid-connect/token", {
    method = "POST",
    body = "client_id="..args["client_id"].."&grant_type="..args["grant_type"].."&username="..args["username"].."&password="..args["password"],
    headers = {
    ["Content-Type"] = "application/x-www-form-urlencoded",
  },
})

if res.status == 200 then
    local reqbody = {
        email = base64.decode_base64url(args["binding"])
    }
    local token = "Bearer "..json.decode(res.body).access_token

    local subres, suberr = httpc:request_uri("http://172.16.0.4:8080/auth/realms/hyc/protocol/openid-connect/userinfo/full", {
        method = "PUT",
        body = json.encode(reqbody),
        headers = {
        ["Content-Type"] = "application/json",
        ["Authorization"] = token,
      },
    })
end

ngx.status = res.status
ngx.say(res.body)