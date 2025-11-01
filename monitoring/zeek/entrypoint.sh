#!/bin/bash
set -e

# Get interface from environment or default to eth0
INTERFACE=${ZEEK_INTERFACE:-eth0}

echo "Starting Zeek on interface: $INTERFACE"

# Update zeek config with the interface
cat > /usr/local/zeek/etc/node.cfg << EOF
[zeek]
type=standalone
host=localhost
interface=$INTERFACE
EOF

# Initialize zeek
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
