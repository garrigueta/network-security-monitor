#!/bin/bash
set -e

# Get interface from environment or default to eth0
INTERFACE=${ZEEK_INTERFACE:-eth0}

echo "Starting Zeek on interface: $INTERFACE"

# Ensure directories exist (they should be mounted from host)
if [ ! -d "/mnt/zeek-logs/logs" ]; then
    echo "Creating logs directory..."
    mkdir -p /mnt/zeek-logs/logs
fi

if [ ! -d "/mnt/zeek-logs/spool" ]; then
    echo "Creating spool directory..."
    mkdir -p /mnt/zeek-logs/spool
fi

# Configure zeekctl to not send mail (we don't have sendmail)
echo "MailTo = " >> /usr/local/zeek/etc/zeekctl.cfg
echo "SendMail = " >> /usr/local/zeek/etc/zeekctl.cfg

# Update zeek config with the interface
cat > /usr/local/zeek/etc/node.cfg << EOF
[zeek]
type=standalone
host=localhost
interface=$INTERFACE
EOF

# Clean up any existing installation
rm -rf /mnt/zeek-logs/spool/installed-scripts-do-not-touch 2>/dev/null || true

# Initialize zeek
echo "Initializing Zeek..."
/usr/local/zeek/bin/zeekctl install

# Start zeek
/usr/local/zeek/bin/zeekctl start

# Give it a moment to start
sleep 5

# Check if zeek is running and logs are being generated
echo "Zeek status:"
/usr/local/zeek/bin/zeekctl status

echo "Log directory contents:"
ls -la /mnt/zeek-logs/logs/

echo "Current log directory contents:"
ls -la /mnt/zeek-logs/logs/current/ || echo "Current directory not yet created"

# Monitor and restart if crashed
while true; do
    sleep 60
    if ! /usr/local/zeek/bin/zeekctl status | grep -q "running"; then
        echo "Zeek crashed, restarting..."
        /usr/local/zeek/bin/zeekctl restart
    fi
done
