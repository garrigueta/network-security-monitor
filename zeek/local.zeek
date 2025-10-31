# Local site policy for Zeek
# Add your custom Zeek scripts here

@load base/frameworks/notice
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssl
@load policy/protocols/ssl/validate-certs

# Enable logging
@load tuning/json-logs
