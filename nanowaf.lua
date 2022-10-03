local cjson = require 'cjson'
local httpc = require 'resty.http'

local _M = {
    _VERSION = '0.0.2.6.dev',
    _AUTHOR  = 'kevin@kevin1986.com',
    Actions = {},
    Methods = {},
    Rules   = {},
    Configs = {
        action_mirror_timeout = 300
    }
}


function _M.Actions.deny(args)
    args.code = args.code or 403
    ngx.exit(args.code)
end

function _M.Actions.hijack(args)
    ngx.status = args.code or 200
    ngx.header["Content-Type"] = args.content_type or 'text/html'
    ngx.say(args.body or '')
    ngx.exit(200)
end

function _M.Actions.mirror(args)
    --[[ 这里需要开启body, 然后解码所有的请求，调包发送给蜜罐端。蜜罐端接请求后返回x-checkstatus: action, {...args}]来执行动作 ]]
    local http = httpc.new()
    local body = nil
    http:set_timeout(args.timeout or _M.Configs.action_mirror_timeout or 300)
    if ngx.req.get_method() == 'POST' or ngx.req.get_method == 'PUT' then
        ngx.req.read_body()
        body = ngx.get_body_data()
    end

    res, err = http:request_uri(args.target, {
        method = ngx.req.get_method(),
        headers = ngx.req.get_headers(-1),
        body = body
    })

    if err==nil then
        if res.headers['x-checkstatus'] ~= nil then 
            action_info = cjson.decode(res.headers["x-checkstatus"])
            if action_info ~= nil then
                _M.Actions[action_info[1]](action_info[2])
            end
        end
    end
end

function _M.Actions.redirect(args)
    ngx.redirect(args.url or '/', args.code or 302)
end

function _M.Actions.tag(args)
    args.zone = args.zone or 'ctx'
    if args.zone == 'ctx' then
        ngx.ctx[args.name or 'tag'] = args.info
    elseif args.zone == 'header' then
        ngx.req.header[args.name or 'x-waf-tag'] = args.info
    end
end

function _M.Methods.regex(text, pattern, reverse)
    if not text then
        return reverse==false
    end
    local to, err = ngx.re.find(text, pattern, 'jo')
    if reverse ~= nil then
        return to==nil
    else
        return to~=nil
    end
end


function _M.Methods.iregex(text, pattern, reverse)
    if not text then
        return reverse==false
    end
    local to, err = ngx.re.find(text, pattern, 'jio')
    if reverse ~= nil then
        return to==nil
    else
        return to~=nil
    end
end


function _M.Methods.ipcontains(ip, cidr, reverse)
    local ip = ip  or '0.0.0.0'
    if not cidr:match('.*/%d+') then cidr = cidr..'/32' end
    local function safe_compare(ip, cidr)
        local o1,o2,o3,o4 = ip:match("(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)" )
        local ipint = 2^24*o1 + 2^16*o2 + 2^8*o3 + o4
        local net, mask = cidr:match("(.*)/(%d+)")
        local n1,n2,n3,n4 = net:match("(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)" )
        local netint = 2^24*n1 + 2^16*n2 + 2^8*n3 + n4
        local netmax = netint+(2^(32-tonumber(mask)))-1
        return ipint <=netmax and ipint >= netint
    end
    local stat, res = pcall(safe_compare, ip, cidr)
    if stat==true then
        if reverse==nil then
            return res
        else
            return not res
        end
    else
        ngx.log(ngx.ERR, res)
        return nil
    end
end

function _M.Methods.equals(text, pattern, reverse)
    if reverse ~= nil then
        return text~=pattern
    else
        return text==pattern
    end
end

function _M.Methods.startswith(text, pattern, reverse)
    text = text or ''
    if reverse ~= nil then
        return string.sub(text, 1, #pattern)~=pattern
    else
        return string.sub(text, 1, #pattern)==pattern
    end
end

function _M.Methods.endswith(text, pattern, reverse)
    text = text or ''
    if reverse ~= nil then
        return string.sub(text, -#pattern)~=pattern
    else
        return string.sub(text, -#pattern)==pattern
    end
end

function _M.Methods.contains(text, pattern, reverse)
    text = text or ''
    if reverse ~= nil then
        return string.find(text,pattern) ~= nil
    else
        return string.find(text,pattern) == nil
    end
end


local function match_single_rule(rules)
    for _, rule in pairs(rules) do
        local mz = rule['mz']
        local method = rule['method']
        local pattern = rule['pattern']
        local isrev = rule['rev']
        if _M.Methods[method] == nil then return end
        local fn = _M.Methods[method]


        if ngx.var[mz] ~= nil then
            if fn(ngx.var[mz], pattern, isrev)==false then return end

        elseif string.sub(mz,1,4) == 'ctx_' then
            if fn(ngx.ctx[string.sub(mz,4)], pattern, isrev)==false then return end

        elseif string.sub(mz ,1,5) == 'http_' then
            if fn(ngx.var[mz], pattern, isrev)==false then return end

        elseif string.sub(mz, 1, 7) == 'cookie_' then
            if fn(ngx.var[mz], pattern, isrev)==false then return end

        elseif string.sub(mz, 1, 4) == 'arg_' then
            if fn(ngx.var[mz], pattern, isrev)==false then return end

        elseif mz == 'method' then
            if fn(ngx.req.get_method(), pattern, isrev)==false then return end

        elseif mz == 'request_uri' then
            if fn(ngx.var.request_uri, pattern, isrev)==false then return end

        elseif mz == 'path' then
            if fn(ngx.req.uri, pattern, isrev)==false then return end

        elseif mz == 'querystring' then
            if fn(ngx.var.query_string, pattern, isrev)==false then return end

        elseif mz == 'body' then
            ngx.req.read_body()
            if fn(ngx.req.get_body_data(), pattern, isrev)==false then return end

        elseif string.sub(mz, 1,9) == 'body_arg_' then
            ngx.req.read_body()
            for k,v in paris(ngx.req.get_post_args()) do
                if k == string.sub(mz, 9) and fn(v, pattern, isrev)==false then return end
            end

        end
    end
    return true
end


function _M.check_request()
    for _, rule in pairs(_M.Rules) do
        if rule.endabled ~= false then
            if match_single_rule(rule.rule)==true then
                if rule.except~=nil and match_single_rule(rule.except)==true then --[[ 如果子规则检测成功，则认为没有问题，执行下一个规则 ]]
                else
                    if(ngx.var.check_rule~=nil) then
                        ngx.var.check_rule = rule.name
                    end
                    if _M.Actions[rule.action[1]] ~= nil then
                        _M.Actions[rule.action[1]](rule.action[2])
                    end
                end
                if rule.pass == nil then break end  --[[ 如果设置了pass，则代表继续检测其他规则, 这样tag在ctx之类的地方就可以作为规则的一部分了 ]]
            end
        end
    end
end


function _M.check_config(premature, config_url, check_interval, http_timeout)
    if premature then return end
    ngx.timer.at(check_interval or 5, _M.check_config, config_url, check_interval, http_timeout)
    if _M.Methods.startswith(config_url, 'file://') then
        local f = io.open(string.sub(config_url, 7), 'r')
        if f ~= nil then
            local conf =f:read("*a")
            _M.Rules = cjson.decode(conf)
        else
            ngx.log(ngx.ERR, err)
        end
    else
        local http, _ = httpc.new()
        http:set_timeout(http_timeout or 1000)
        res, err = http:request_uri(config_url, {ssl_verify=false})
        if err~=nil then
            ngx.log(ngx.ERR, err)
        else
            _M.Rules = cjson.decode(res.body)
        end
    end
end

return _M
