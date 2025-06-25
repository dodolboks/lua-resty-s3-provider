local util = require "resty.s3_util"
local s3_auth = require "resty.s3_auth"
local cjson = require "cjson"
local xml = require "resty.s3_xml"
local s3_multi_upload = require("resty.s3_multi_upload")

local ok, new_tab = pcall(require, "table.new")
if not ok then
    new_tab = function (narr, nrec) return {} end
end

local function proc_uri(uri)
    if uri == nil then
        return nil
    end

    if uri and string.len(uri) > 0 and string.sub(uri, 1,1) == '/' then
        uri = string.sub(uri, 2)
    end

    return uri
end

-- Predefined S3-compatible providers
local PROVIDERS = {
    aws = {
        host_template = "{bucket}.s3.{region}.amazonaws.com",
        host_template_us_east_1 = "{bucket}.s3.amazonaws.com",
        default_region = "us-east-1",
        service_name = "s3",
        use_https = true,
        path_style = false,
        delete_multi_url_template = "/?delete"
    },
    r2 = {
        host_template = "{account_id}.r2.cloudflarestorage.com",
        default_region = "auto",
        service_name = "s3",
        use_https = true,
        path_style = true,
        delete_multi_url_template = "/{bucket}?delete"
    },
    linode = {
        host_template = "{region}.linodeobjects.com",
        default_region = "us-east-1",
        service_name = "s3",
        use_https = true,
        path_style = true,
        delete_multi_url_template = "/{bucket}?delete"
    },
    wasabi = {
        host_template = "s3.{region}.wasabisys.com",
        default_region = "us-east-1",
        service_name = "s3",
        use_https = true,
        path_style = true,
        delete_multi_url_template = "/{bucket}?delete"
    },
    digitalocean = {
        host_template = "{region}.digitaloceanspaces.com",
        default_region = "nyc3",
        service_name = "s3",
        use_https = true,
        path_style = true,
        delete_multi_url_template = "/{bucket}?delete"
    },
    custom = {
        -- For custom S3-compatible endpoints
        host_template = "{host}",
        default_region = "us-east-1",
        service_name = "s3",
        use_https = true,
        path_style = true,
        delete_multi_url_template = "/{bucket}?delete"
    }
}

local _M = new_tab(0, 100)
_M._VERSION = '0.3.0'

local mt = { __index = _M }

function _M:new(aws_access_key, aws_secret_key, aws_bucket, args)
    if not aws_access_key then
        return nil, "must provide aws_access_key"
    end
    if not aws_secret_key then
        return nil, "must provide aws_secret_key"
    end
    if not aws_bucket then
        return nil, "must provide aws_bucket"
    end
    
    args = args or {}

    -- Default values
    local timeout = args.timeout or 10 * 1000
    local provider = args.provider or "aws"
    local aws_region = args.aws_region or args.region
    local use_https = args.use_https
    local path_style = args.path_style
    local host = args.host
    local account_id = args.account_id -- For R2
    
    -- Get provider configuration
    local provider_config = PROVIDERS[provider]
    if not provider_config then
        return nil, "unsupported provider: " .. tostring(provider)
    end
    
    -- Set defaults from provider config
    aws_region = aws_region or provider_config.default_region
    if use_https == nil then
        use_https = provider_config.use_https
    end
    if path_style == nil then
        path_style = provider_config.path_style
    end
    
    -- Build host if not provided
    if not host then
        local host_template = provider_config.host_template
        
        -- Special case for AWS us-east-1
        if provider == "aws" and aws_region == "us-east-1" and provider_config.host_template_us_east_1 then
            host_template = provider_config.host_template_us_east_1
        end
        
        -- Replace placeholders
        host = host_template:gsub("{bucket}", aws_bucket)
        host = host:gsub("{region}", aws_region)
        if account_id then
            host = host:gsub("{account_id}", account_id)
        end
        if args.custom_host then
            host = host:gsub("{host}", args.custom_host)
        end
    end
    
    local aws_service = provider_config.service_name
    local auth = s3_auth:new(aws_access_key, aws_secret_key, aws_bucket, aws_region, aws_service, nil)
    
    -- Determine if we should add bucket to URI (path-style)
    local add_bucket_to_uri = path_style
    
    -- Protocol prefix
    local protocol = use_https and "https://" or "http://"
    
    return setmetatable({
        auth = auth,
        host = host,
        aws_bucket = aws_bucket,
        add_bucket_to_uri = add_bucket_to_uri,
        aws_region = aws_region,
        timeout = timeout,
        provider = provider,
        provider_config = provider_config,
        protocol = protocol,
        use_https = use_https,
        path_style = path_style
    }, mt)
end

function _M:get_short_uri(key)
    local short_uri = '/' .. proc_uri(key)
    if self.add_bucket_to_uri then
        short_uri = '/' .. self.aws_bucket .. short_uri
    end
    return short_uri
end

function _M:get_full_url(short_uri)
    return self.protocol .. self.host .. util.uri_encode(short_uri, false)
end

-- http://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectHEAD.html
function _M:head(key)
    local short_uri = self:get_short_uri(key)
    local myheaders = util.new_headers()
    local authorization = self.auth:authorization_v4("HEAD", short_uri, myheaders, nil)

    local url = self:get_full_url(short_uri)
    local res, err, req_debug = util.http_head(url, myheaders, self.timeout)
    if not res then
        ngx.log(ngx.ERR, "fail request to s3 service: [", req_debug, "] err: ", err)
        return false, "request to s3 failed", 500
    end

    ngx.log(ngx.INFO, "s3 request:", url, ", status:", res.status, ",body:", tostring(res.body))

    if res.status ~= 200 then
        if res.status == 404 then
            ngx.log(ngx.INFO, "object [", key, "] not exist")
            return false, "not-exist", res.status
        else
            ngx.log(ngx.ERR, "request [ ", req_debug,  " ] failed! status:", res.status, ", body:", tostring(res.body))
            return false, res.body or "request to s3 failed", res.status
        end
    end

    return true, res
end

-- http://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectGET.html
function _M:get(key)
    local short_uri = self:get_short_uri(key)
    local myheaders = util.new_headers()
    local authorization = self.auth:authorization_v4("GET", short_uri, myheaders, nil)

    local url = self:get_full_url(short_uri)
    local res, err, req_debug = util.http_get(url, myheaders, self.timeout)
    if not res then
        ngx.log(ngx.ERR, "fail request to s3 service: [", req_debug, "] err: ", err)
        return false, "request to s3 failed", 500
    end

    ngx.log(ngx.INFO, "s3 request:", url, ", status:", res.status, ",body:", tostring(res.body))

    if res.status ~= 200 then
        if res.status == 404 then
            ngx.log(ngx.INFO, "object [", key, "] not exist")
            return false, "not-exist", res.status
        else
            ngx.log(ngx.ERR, "request [ ", req_debug,  " ] failed! status:", res.status, ", body:", tostring(res.body))
            return false, res.body or "request to s3 failed", res.status
        end
    end

    ngx.log(ngx.INFO, "s3 returned: body:", res.body)

    return true, res.body
end

-- http://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectPUT.html
function _M:put(key, value, headers)
    local short_uri = self:get_short_uri(key)
    headers = headers or util.new_headers()
    local authorization = self.auth:authorization_v4("PUT", short_uri, headers, value)

    local url = self:get_full_url(short_uri)
    ngx.log(ngx.INFO, "----- url: ", url)
    
    local res, err, req_debug = util.http_put(url, value, headers, self.timeout)
    if not res then
        ngx.log(ngx.ERR, "fail request to s3 service: [ ", req_debug, " ] err: ", err)
        return false, "request to s3 failed", 500
    end

    ngx.log(ngx.INFO, "s3 request:", req_debug, ", status:", res.status, ",body:", tostring(res.body))

    if res.status ~= 200 then
        ngx.log(ngx.ERR, "request [ ", req_debug, " ] failed! status:", res.status, ", body:", tostring(res.body))
        return false, res.body or "request to s3 failed", res.status
    end

    ngx.log(ngx.INFO, "s3 returned: body: [", res.body, "]")

    return true, res.body
end

-- https://docs.aws.amazon.com/AmazonS3/latest/API/API_CopyObject.html
function _M:copy(key, source, headers)
    headers = headers or util.new_headers()
    
    -- Handle path-style vs virtual-hosted-style for copy source
    local copy_source = source
    if self.path_style and not string.find(source, "/") then
        -- If path-style and source doesn't contain bucket, add it
        copy_source = "/" .. self.aws_bucket .. "/" .. source
    end
    
    headers["x-amz-copy-source"] = ngx.escape_uri(copy_source)

    return self:put(key, "", headers)
end

-- http://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectDELETE.html
function _M:delete(key)
    local short_uri = self:get_short_uri(key)
    local myheaders = util.new_headers()
    local authorization = self.auth:authorization_v4("DELETE", short_uri, myheaders, nil)

    local url = self:get_full_url(short_uri)
    local res, err, req_debug = util.http_del(url, myheaders, self.timeout)
    if not res then
        ngx.log(ngx.ERR, "fail request to s3 service: [ ", req_debug, " ] err: ", err)
        return false, "request to s3 failed", 500
    end

    ngx.log(ngx.INFO, "s3 request:", req_debug, ", status:", res.status, ",body:", tostring(res.body))

    if res.status ~= 204 then
        ngx.log(ngx.ERR, "request [ ", req_debug, " ] failed! status:", res.status, ", body:", tostring(res.body))
        return false, res.body or "request to s3 failed", res.status
    end

    ngx.log(ngx.INFO, "s3 returned: body: [", res.body, "]")

    return true, res.body
end

-- http://docs.aws.amazon.com/AmazonS3/latest/API/multiobjectdeleteapi.html
function _M:deletes(keys, quiet)
    if type(keys) ~= 'table' or #keys < 1 then
        ngx.log(ngx.ERR, "args [keys] invalid!")
        return false, "args-invalid"
    end
    
    -- Build URL based on provider configuration
    local delete_url_template = self.provider_config.delete_multi_url_template
    local url = self.protocol .. self.host .. delete_url_template:gsub("{bucket}", self.aws_bucket)
    
    local myheaders = util.new_headers()
    local Object = {}
    for _, key in ipairs(keys) do
        table.insert(Object, {Key=key})
    end
    if quiet == nil then
        quiet = true
    end
    local body = {Delete={Quiet=quiet, Object=Object}}
    body = xml.dumps(body)
    local content_md5 = ngx.encode_base64(ngx.md5_bin(body))
    myheaders["content-md5"] = content_md5
    
    local authorization = self.auth:authorization_v4("POST", url, myheaders, body)

    local res, err, req_debug = util.http_post(url, body, myheaders, self.timeout)
    if not res then
        ngx.log(ngx.ERR, "fail request to s3 service: [ ", req_debug, " ] err: ", err)
        return false, "request to s3 failed", 500
    end

    ngx.log(ngx.INFO, "s3 request:", req_debug, ", status:", res.status, ",body:", tostring(res.body))

    if res.status ~= 200 then
        ngx.log(ngx.ERR, "request [ ", req_debug, " ] failed! status:", res.status, ", body:", tostring(res.body))
        return false, res.body or "request to s3 failed", res.status
    end

    ngx.log(ngx.INFO, "s3 returned: body:", res.body)
    local doc, err = xml.loads(res.body)
    if doc == nil then
        return false, "xml-invalid", 500
    end

    return true, doc
end

-- http://docs.aws.amazon.com/AmazonS3/latest/API/v2-RESTBucketGET.html
function _M:list(prefix, delimiter, page_size, marker)
    prefix = prefix or ""
    local args = {prefix=prefix}

    local url = self.protocol .. self.host .. "/"
    if self.add_bucket_to_uri then
        url = url .. self.aws_bucket
    end
    if delimiter then
        args.delimiter = delimiter
    end
    if page_size then
        args["max-keys"] = tostring(tonumber(page_size))
    end
    if marker then
        args.marker = tostring(marker)
    end
    url = url .. "?" .. ngx.encode_args(args)

    local myheaders = util.new_headers()
    local authorization = self.auth:authorization_v4("GET", url, myheaders, nil)

    local res, err, req_debug = util.http_get(url, myheaders, self.timeout)
    if not res then
        ngx.log(ngx.ERR, "fail request to s3 service: [", req_debug, "] err: ", err)
        return false, "request to s3 failed", 500
    end

    ngx.log(ngx.INFO, "s3 request:", url, ", status:", res.status, ",body:", tostring(res.body))

    if res.status ~= 200 then
        if res.status == 404 then
            ngx.log(ngx.INFO, "object [", prefix, "] not exist")
            return false, "not-exist", res.status
        else
            ngx.log(ngx.ERR, "request [ ", req_debug,  " ] failed! status:", res.status, ", body:", tostring(res.body))
            return false, res.body or "request to s3 failed", res.status
        end
    end

    ngx.log(ngx.INFO, "s3 returned: body:", res.body)
    local doc, err = xml.loads(res.body)
    if doc == nil then
        return false, "xml-invalid", 500
    end
    if doc.ListBucketResult == nil then
       return false, "no-list-result", 500
    end
    return true, doc
end

-- http://docs.aws.amazon.com/AmazonS3/latest/API/mpUploadInitiate.html
function _M:start_multi_upload(key, myheaders)
    local short_uri = self:get_short_uri(key)
    local url = self:get_full_url(short_uri) .. "?uploads"

    myheaders = myheaders or util.new_headers()
    local authorization = self.auth:authorization_v4("POST", url, myheaders, nil)
    ngx.log(ngx.INFO, "headers [", cjson.encode(myheaders), "]")

    local res, err, req_debug = util.http_post(url, "", myheaders, self.timeout)
    if not res then
        ngx.log(ngx.ERR, "fail request to s3 service: [", req_debug, "] err: ", err)
        return false, "request to s3 failed", 500
    end

    ngx.log(ngx.INFO, "s3 request:", url, ", status:", res.status, ",body:", tostring(res.body))

    if res.status ~= 200 then
        ngx.log(ngx.ERR, "request [ ", req_debug,  " ] failed! status:", res.status, ", body:", tostring(res.body))
        return false, res.body or "request to s3 failed", res.status
    end

    ngx.log(ngx.INFO, "s3 returned: body:", res.body)
    local doc, err = xml.loads(res.body)
    if doc == nil then
        return false, "xml-invalid", 500
    end
    if type(doc.InitiateMultipartUploadResult) ~= "table" then
        return false, "xml-invalid", 500
    end
    local uploadResult = doc.InitiateMultipartUploadResult

    local upload = s3_multi_upload:new(self.auth, self.host, self.timeout, uploadResult)
    return true, upload
end

function _M:authorization_v4(method, url, headers)
    return self.auth:authorization_v4_internal(method, url, headers)
end

-- Helper function to get supported providers
function _M.get_supported_providers()
    local providers = {}
    for name, config in pairs(PROVIDERS) do
        table.insert(providers, name)
    end
    return providers
end

return _M