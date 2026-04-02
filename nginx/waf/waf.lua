ngx.log(ngx.INFO, "[WAF] Request received: ", ngx.var.request_uri)

local args = ngx.req.get_uri_args()
for k, v in pairs(args) do
    if type(v) == "table" then v = table.concat(v, ",") end
    if tostring(v):match("<script>") then
        ngx.status = ngx.HTTP_FORBIDDEN
        ngx.say("Blocked by custom WAF.")
        ngx.exit(ngx.HTTP_FORBIDDEN)
    end
end

-- 通過ログ
ngx.log(ngx.INFO, "[WAF] Request allowed.")
