#!/bin/sh
# NOTE: this script is for illustration purpose only. For security, the script
# should not be used in production envrionment without modification.

PATH=/usr/bin:/usr/sbin:/bin:/sbin

if ! [ -x /usr/bin/wg ]; then
    echo "WireGuard command line tool not found at /usr/bin/wg. Aborting"
    exit 1
fi

sudo ip link add dev wg0 type wireguard
sudo ip addr add 10.0.0.3/24 dev wg0
sudo ip link set wg0 up
sudo /usr/bin/wg setconf wg0 /wg_config/wg0.conf
