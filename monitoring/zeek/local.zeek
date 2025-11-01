# Local site policy for Zeek
# Add your custom Zeek scripts here

@load base/frameworks/notice
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssl
@load policy/protocols/ssl/validate-certs

# Enable JSON logging for better Loki integration
@load tuning/json-logs

# Additional logging modules for comprehensive monitoring
@load base/protocols/ftp
@load base/protocols/ssh
@load base/protocols/smtp
@load base/protocols/dhcp
@load policy/misc/loaded-scripts
@load policy/tuning/json-logs
