require 'rack/static'

map "/" do
  use Rack::Static, urls: ["/assets"], root: Dir.pwd

  run lambda { |env|
    headers = {
      "content-type"              => "text/html; charset=utf-8",
      "cache-control"             => "private, max-age=0, must-revalidate",
      "strict-transport-security" => "max-age=16070400",
      "x-frame-options"           => "SAMEORIGIN",
      "x-content-type-options"    => "nosniff",
      "x-xss-protection"          => "1; mode=block",
      "content-security-policy"   => "default-src 'none'; script-src 'self' code.jquery.com netdna.bootstrapcdn.com; style-src 'self' 'unsafe-inline' netdna.bootstrapcdn.com; font-src netdna.bootstrapcdn.com; img-src *",
      "x-content-security-policy" => "default-src 'none'; script-src 'self' code.jquery.com netdna.bootstrapcdn.com; style-src 'self' 'unsafe-inline' netdna.bootstrapcdn.com; font-src netdna.bootstrapcdn.com; img-src *",
      "x-webkit-csp"              => "default-src 'none'; script-src 'self' code.jquery.com netdna.bootstrapcdn.com; style-src 'self' 'unsafe-inline' netdna.bootstrapcdn.com; font-src netdna.bootstrapcdn.com; img-src *"
    }

    body = File.open("#{Dir.pwd}/index.html", File::RDONLY).read

    [200, headers, [body]]
  }
end
