local sha2 = require "resty.s3_provider_sha2"
local util = require "resty.s3_provider_util"

local NEW_LINE = "\n"

local ok, new_tab = pcall(require, "table.new")
if not ok then
    new_tab = function (narr, nrec) return {} end
end

-- Predefined S3-compatible providers
local PROVIDERS = {
    aws = {
        endpoint_template = "{bucket}.s3.{region}.amazonaws.com",
        default_region = "us-east-1",
        service_name = "s3"
    },
    r2 = {
        endpoint_template = "{account_id}.r2.cloudflarestorage.com",
        default_region = "auto",
        service_name = "s3",
        path_style = true  -- R2 uses path-style by default
    },
    linode = {
        endpoint_template = "{region}.linodeobjects.com",
        default_region = "us-east-1",
        service_name = "s3",
        path_style = false  -- Linode uses virtual-hosted style
    },
    digitalocean = {
        endpoint_template = "{region}.digitaloceanspaces.com",
        default_region = "nyc3",
        service_name = "s3"
    },
    wasabi = {
        endpoint_template = "s3.{region}.wasabisys.com",
        default_region = "us-east-1",
        service_name = "s3"
    },
    minio = {
        endpoint_template = "{endpoint}",
        default_region = "us-east-1",
        service_name = "s3",
        path_style = true
    }
}

local function get_datetime()
    local datetime = ngx.utctime()
    local m, err = ngx.re.match(datetime, "(\\d{4})-(\\d{2})-(\\d{2}) (\\d{2}):(\\d{2}):(\\d{2})")
    if err == nil and (type(m)=='table' and #m == 6) then
        local date = m[1] .. m[2] .. m[3]
        local time = m[4] .. m[5] .. m[6]
        return date, time, date .. "T" .. time .. "Z"
    else
        local datetime = os.date("!%Y%m%dT%H%M%S")
        local x = string.find(datetime, 'T')
        local date, time = string.sub(datetime, 1, x-1), string.sub(datetime, x+1)
        return date, time, date .. "T" .. time .. "Z"
    end
end

local _M = new_tab(0, 100)
_M._VERSION = '0.4.0'

local hmac_sha256 = util.hmac_sha256

local mt = { __index = _M }

function _M:new(config, aws_secret_key, aws_bucket, aws_region, aws_service, datetime_cb)
    -- Support both old style parameters and new config table
    local aws_access_key
    local provider, endpoint, account_id, path_style
    
    if type(config) == "string" then
        -- Old style: new(aws_access_key, aws_secret_key, aws_bucket, aws_region, aws_service, datetime_cb)
        aws_access_key = config
        -- Parameters are already passed as function arguments
        provider = "aws"
    else
        -- New style: new({...})
        aws_access_key = config.access_key
        aws_secret_key = config.secret_key
        aws_bucket = config.bucket
        aws_region = config.region
        aws_service = config.service
        datetime_cb = config.datetime_cb
        provider = config.provider or "aws"
        endpoint = config.endpoint
        account_id = config.account_id
        path_style = config.path_style
    end
    
    if not aws_access_key then
        return nil, "must provide access_key"
    end
    if not aws_secret_key then
        return nil, "must provide secret_key"
    end
    if not aws_bucket then
        return nil, "must provide bucket"
    end

    -- Get provider configuration
    local provider_config = PROVIDERS[provider]
    if not provider_config then
        return nil, "unsupported provider: " .. tostring(provider)
    end

    -- Set defaults from provider config
    if not aws_region then
        aws_region = provider_config.default_region
    end
    if not aws_service then
        aws_service = provider_config.service_name
    end
    if datetime_cb == nil then
        datetime_cb = get_datetime
    end
    if path_style == nil then
        path_style = provider_config.path_style or false
    end

    -- Build endpoint
    local host
    if endpoint then
        -- Custom endpoint provided
        host = endpoint
    else
        -- Build from template
        host = provider_config.endpoint_template
        host = string.gsub(host, "{bucket}", aws_bucket)
        host = string.gsub(host, "{region}", aws_region)
        host = string.gsub(host, "{account_id}", account_id or "")
        host = string.gsub(host, "{endpoint}", endpoint or "localhost:9000")
    end

    return setmetatable({ 
        aws_access_key = aws_access_key, 
        aws_secret_key = aws_secret_key, 
        aws_bucket = aws_bucket, 
        aws_region = aws_region, 
        aws_service = aws_service,
        datetime_cb = datetime_cb,
        provider = provider,
        host = host,
        path_style = path_style,
        account_id = account_id
    }, mt)
end

-- Helper function to get the appropriate host header
function _M:get_host()
    if self.path_style then
        -- For path-style, bucket is in the path, not the host
        return self.host
    else
        -- For virtual-hosted style, bucket is in the host
        if self.provider == "aws" then
            return self.aws_bucket .. ".s3." .. self.aws_region .. ".amazonaws.com"
        elseif self.provider == "linode" then
            return self.aws_bucket .. "." .. self.aws_region .. ".linodeobjects.com"
        else
            -- For other providers, prepend bucket to host
            return self.aws_bucket .. "." .. self.host
        end
    end
end

-- Helper function to build the full URL
function _M:build_url(path)
    local host = self:get_host()
    local url_path = path or "/"
    
    if self.path_style then
        -- Path-style: https://host/bucket/object
        if not string.match(url_path, "^/" .. self.aws_bucket) then
            url_path = "/" .. self.aws_bucket .. url_path
        end
    end
    
    return url_path
end

local function uri_encode(arg, encodeSlash, cd)
    return util.uri_encode(arg, encodeSlash, cd)
end

local function URI_ENCODE(arg, cd)
    return uri_encode(arg, false, cd)
end

local function parse_args(args)
    local kv_args = {}
    for arg in string.gmatch(args, "[^&]+") do
        local x = string.find(arg, "=")
        local key, value = nil, nil
        if x then
            key = string.sub(arg, 1, x-1)
            value = string.sub(arg, x+1)
        else
            key = arg
            value = ""
        end
        if kv_args[key] then
            local values = kv_args[key]
            if type(values) ~= 'table' then
                values = {values}
            end
            table.insert(values,value)
            value = values
        end
        kv_args[key] = value
    end

    return kv_args
end

local function _query_string(args, cd)
    if args == nil then
        return ""
    end
    args = parse_args(args)

    local keys = {}
    for key, _ in pairs(args) do 
        table.insert(keys, key)
    end
    table.sort(keys)
    local key_values = {}
    for _, key in ipairs(keys) do 
        local value = args[key]
        if type(value) == 'table' then
            table.sort(value)
            for _, value_sub in ipairs(value) do 
                table.insert(key_values, uri_encode(key, true, cd) .. "=" .. uri_encode(value_sub, true, cd))
            end
        else
            table.insert(key_values, uri_encode(key, true, cd) .. "=" .. uri_encode(value, true, cd))
        end
    end
    return table.concat(key_values, "&")
end

local function startswith(str, startstr)
   return startstr=='' or string.sub(str,1, string.len(startstr))==startstr
end

local function endswith(str,endstr)
   return endstr=='' or string.sub(str,-string.len(endstr))==endstr
end

local function uri2short(uri)
    if startswith(uri, "http://") then
        local first = string.find(uri, "/", 8)
        if first then
            uri = string.sub(uri, first)
        end
    elseif startswith(uri, "https://") then
        local first = string.find(uri, "/", 9)
        if first then
            uri = string.sub(uri, first)
        end
    end
    if uri and string.sub(uri, 1,1) ~= "/" then
        uri = "/" .. uri
    end
    -- Handle: // --> /
    uri = string.gsub(uri, "//", "/")
    -- Handle: /./ --> / 
    uri = string.gsub(uri, "/%./", "/")

    -- Handle: /path/to/../.. --> /
    local relatives = 0
    for i = 1, 16 do 
        if uri and endswith(uri, "/..") then
            uri = string.sub(uri, 1, #uri-3)
            relatives = i
        else
            break
        end 
    end

    for i = 1, relatives do
        local slash_pos = uri:reverse():find("/")
        if slash_pos then
            local pos = #uri - slash_pos
            uri = string.sub(uri, 1, pos)
        end
    end
    if uri == "" then
        uri = "/"
    end
    return uri
end

local function trim (s)
    return (string.gsub(s, "^%s*(.-)%s*$", "%1"))
end

local function replace_spaces(s)
    return (string.gsub(s, "[ ]+", " "))
end

local function proc_headers(headers)
    local t = headers
    local headers_lower = {}
    local signed_headers = {}
    local header_values = {}
    
    for k,v in pairs(t) do
        k = string.lower(k)
        if type(v) == 'table' then
            v = table.concat(v, ",")
        end
        table.insert(signed_headers, k)
        headers_lower[k] = v
    end
    
    table.sort(signed_headers)
    for _, k in ipairs(signed_headers) do 
        table.insert(header_values, k .. ":" .. replace_spaces(trim(headers_lower[k])) .. '\n')
    end
    return table.concat(header_values), table.concat(signed_headers, ";")
end

-- Task 1: Create a Canonical Request
local function create_canonical_request(req)
    local uri, args = util.short_url_parse(req.url)

    local header_str, signed_headers = proc_headers(req.headers)
    local hashed_payload = req.content_sha256
    local query_string = nil
    if req.is_form_urlencoded then
        query_string = _query_string(req.body, req.cd)
    else
        query_string = _query_string(args, req.cd)
    end

    local requestStr =  req.method .. NEW_LINE ..
                        URI_ENCODE(uri, req.cd) .. NEW_LINE ..
                        query_string .. NEW_LINE ..
                        header_str .. NEW_LINE ..
                        signed_headers .. NEW_LINE ..
                        hashed_payload
    ngx.log(ngx.INFO, "Canonical Request[[[\n", requestStr, "\n]]]")

    return requestStr, signed_headers
end

-- Task 2: Create a String to Sign
local function create_string_to_sign(req, aws_region, aws_service, date, time)
    local algorithm = "AWS4-HMAC-SHA256"
    local timeStampISO8601Format = date .. "T" .. time .. "Z"
    local scope = string.format("%s/%s/%s/aws4_request", date, aws_region, aws_service)
    
    local request, signed_headers = create_canonical_request(req)
    local sha265hash_of_request = sha2.sha256(request)
    
    local string_to_sign =  algorithm .. NEW_LINE ..
                            timeStampISO8601Format .. NEW_LINE .. 
                            scope .. NEW_LINE .. 
                            sha265hash_of_request
    ngx.log(ngx.INFO, "String to Sign:[[[\n", string_to_sign, "\n]]]")

    return string_to_sign, {algorithm=algorithm, scope=scope, signed_headers=signed_headers, request=request}
end

-- Task 3: Calculate Signature
local function calculate_sign(req, secret_access_key, aws_region, aws_service, date, time)
    local date_key = hmac_sha256("AWS4" .. secret_access_key, date)
    local date_region_key = hmac_sha256(date_key, aws_region)
    local signing_key = hmac_sha256(hmac_sha256(date_region_key, aws_service), "aws4_request")
    local string_to_sign, extinfo = create_string_to_sign(req, aws_region, aws_service, date, time)
    extinfo.string_to_sign = string_to_sign
    return hmac_sha256(signing_key, string_to_sign, true), extinfo
end

function _M:sign_v4(method, url, headers, body, date, time)
    local content_type = headers["content-type"]
    local content_sha256 = headers["x-amz-content-sha256"]
    local is_form_urlencoded = content_type ~= nil and startswith(content_type, "application/x-www-form-urlencoded")
    
    if content_sha256 == nil then
        if is_form_urlencoded then
            content_sha256 = sha2.sha256("")
        else
            content_sha256 = sha2.sha256(body or "")
        end
    end

    local aws_service = self.aws_service
    if not headers["Host"] then
        headers["Host"] = self:get_host()
    else
        if not aws_service then
            local host = headers.host
            local idx = string.find(host, "%.")
            if idx then
                aws_service = string.sub(host, 1, idx-1)
            end
        end
    end
    
    url = uri2short(url)

    local req = {
        method = method, 
        url = url, 
        headers = headers, 
        body = body, 
        content_sha256 = content_sha256, 
        is_form_urlencoded = is_form_urlencoded, 
        cd = self.cd
    }
    
    local signature, extinfo = calculate_sign(req, self.aws_secret_key, self.aws_region, aws_service, date, time)
    extinfo.url = url
    return signature, extinfo
end

function _M:authorization_v4(method, url, headers, body)
    local date, time, datetime = self.datetime_cb()
    local content_sha256 = sha2.sha256(body or "")
    headers["x-amz-content-sha256"] = content_sha256
    headers["x-amz-date"] = datetime
    return _M.authorization_v4_internal(self, method, url, headers)
end

function _M:authorization_v4_4test(method, url, headers, body)
    return _M.authorization_v4_internal(self, method, url, headers, body)
end

local function get_date_and_time_s3(datetime)
    if not datetime then
        return nil
    end
    local ti = string.find(datetime, "T")
    if ti then
        local zi = string.find(datetime, "Z", ti-1)
        if zi then
            return string.sub(datetime, 1, ti-1), string.sub(datetime, ti+1, zi-1)
        end
        return nil
    end
    return nil
end

function _M:authorization_v4_internal(method, url, headers, body)
    local datetime = headers["x-amz-date"]
    local date, time = nil, nil
    if datetime then
        date, time = get_date_and_time_s3(datetime)
        if date == nil then
            date, time, datetime = self.datetime_cb()
            headers["x-amz-date"] = datetime
        end
    else
        headers["date"] = nil
        date, time, datetime = self.datetime_cb()
        headers["x-amz-date"] = datetime
    end
    
    local signature, extinfo = _M.sign_v4(self, method, url, headers, body, date, time)
    local algorithm, scope, signed_headers = extinfo.algorithm, extinfo.scope, extinfo.signed_headers

    local authorization = string.format("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s", 
                                    algorithm, self.aws_access_key, scope, signed_headers, signature)
    
    headers["Authorization"] = authorization
    extinfo.signature = signature
    extinfo.authorization = authorization
    return authorization, signature, extinfo
end

-- Convenience method to create a simple HTTP client request
function _M:create_request(method, path, headers, body)
    headers = headers or {}
    local url = self:build_url(path)
    headers["Host"] = self:get_host()
    
    local auth, sig, extinfo = self:authorization_v4(method, url, headers, body)
    
    return {
        method = method,
        url = "https://" .. headers["Host"] .. url,
        headers = headers,
        body = body,
        authorization = auth,
        signature = sig,
        extinfo = extinfo
    }
end

return _M