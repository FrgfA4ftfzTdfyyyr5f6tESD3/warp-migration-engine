#!/bin/bash
set -e

PORT=${1:-2632}
echo "=========================================================="
echo "  Deploying Cloudflare WARP Handshake Migration Relay     "
echo "  Port: $PORT                                            "
echo "=========================================================="

cp -f masque-relay /usr/local/bin/masque-relay
chmod +x /usr/local/bin/masque-relay

sed -i "s|masque-relay [0-9]*|masque-relay $PORT|g" masque-relay.service
cp -f masque-relay.service /etc/systemd/system/masque-relay.service

systemctl daemon-reload
systemctl enable --now masque-relay

echo "=========================================================="
echo "  Relay is now active and listening on UDP port $PORT!     "
echo "  Check status with: systemctl status masque-relay        "
echo "=========================================================="
