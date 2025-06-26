package = "lua-resty-s3-provider"
version = "0.4-0"
source = {
   url = "git+https://github.com/dodolboks/lua-resty-s3-provider.git"
}

description = {
   summary = "a aws s3 client for ngx_lua with support for other s3 compitable provider, like r2, linodeobject & other",
   homepage = "https://github.com/dodolboks/lua-resty-s3-provider",
   license = "BSD"
}
dependencies = {
   "lua ~> 5.1"
}
build = {
   type = "builtin",
   modules = {
      ["resty.s3"] = "lib/resty/s3_provider.lua",
      ["resty.s3_auth"] = "lib/resty/s3_provider_auth.lua",
      ["resty.s3_multi_upload"] = "lib/resty/s3_provider_multi_upload.lua",
      ["resty.s3_sha2"] = "lib/resty/s3_provider_sha2.lua",
      ["resty.s3_util"] = "lib/resty/s3_provider_util.lua",
      ["resty.s3_xml"] = "lib/resty/s3_provider_xml.lua"
   }
}
