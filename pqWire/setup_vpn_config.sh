#!/bin/sh

# set up config files for two clients and one server
MKDIR='mkdir -p'
SERVER_DIR=server
CLIENT_DIR=client
INSTALL_CONFIG_DIR='/wg_config'
SCRIPT='run.sh'
PRIKEY=prikey
PUBKEY=pubkey
SERVER_PUBKEY="server-$PUBKEY"
CLIENT_PUBKEY="client-$PUBKEY"

# NOTE: fill in the actual ip address
EXT_SERVER_IP='192.168.0.1'
VPN_RANGE=24
SERVER_IP='10.0.0.1'
CLIENT_IP='10.0.0'
IF='wg0'
SERVER_PORT=12345

# path to wireguard command line tool
WG=/usr/bin/wg

if ! [ -x $WG ]; then
    echo "WireGuard command line tool not found at $WG. Aborting"
    exit 1
fi

genkey() {
    GEN_DIR=$1
    PRIKEY_NAME=$2
    PUBKEY_NAME=$3
    $WG mckey "$GEN_DIR/$PRIKEY_NAME" "$GEN_DIR/$PUBKEY_NAME"
}

cat <<EOF
Generating configuration files based on the following settings:
    server external IP: $EXT_SERVER_IP
    server VPN IP: $SERVER_IP
    server listening port: $SERVER_PORT
    client-1 VPN IP: $CLIENT_IP.2
    client-2 VPN IP: $CLIENT_IP.3
EOF

if [ -d "$SERVER_DIR" ]; then
    echo "Target dir exists: $SERVER_DIR! Aborting"
    exit 1
fi

if [ -d "$CLIENT_DIR-1" ]; then
    echo "Target dir exists: $CLIENT_DIR-1! Aborting"
    exit 1
fi

if [ -d "$CLIENT_DIR-2" ]; then
    echo "Target dir exists: $CLIENT_DIR-2! Aborting"
    exit 1
fi

# generate the keys for server and 2 clients
$MKDIR "$SERVER_DIR"
genkey "$SERVER_DIR" "$PRIKEY" "$PUBKEY"

$MKDIR "$CLIENT_DIR-1"
genkey "$CLIENT_DIR-1" "$PRIKEY" "$PUBKEY"

$MKDIR "$CLIENT_DIR-2"
genkey "$CLIENT_DIR-2" "$PRIKEY" "$PUBKEY"

# generate the config for server
cat <<EOF > "$SERVER_DIR/$IF.conf"
[Interface]
McEliecePrivateKey = $INSTALL_CONFIG_DIR/$PRIKEY
McEliecePublicKey = $INSTALL_CONFIG_DIR/$PUBKEY
ListenPort = $SERVER_PORT

[Peer]
McEliecePublicKey = $INSTALL_CONFIG_DIR/$CLIENT_PUBKEY-1
AllowedIPs = $CLIENT_IP.2

[Peer]
McEliecePublicKey = $INSTALL_CONFIG_DIR/$CLIENT_PUBKEY-2
AllowedIPs = $CLIENT_IP.3
EOF

# generate config for the clients
SERVER_PUBKEY_PATH="$INSTALL_CONFIG_DIR/$SERVER_PUBKEY"

cat <<EOF > "$CLIENT_DIR-1/$IF.conf"
[Interface]
McEliecePrivateKey = $INSTALL_CONFIG_DIR/$PRIKEY
McEliecePublicKey = $INSTALL_CONFIG_DIR/$PUBKEY

[Peer]
McEliecePublicKey = $SERVER_PUBKEY_PATH
Endpoint = $EXT_SERVER_IP:$SERVER_PORT
AllowedIPs = $SERVER_IP
EOF

cat <<EOF > "$CLIENT_DIR-2/$IF.conf"
[Interface]
McEliecePrivateKey = $INSTALL_CONFIG_DIR/$PRIKEY
McEliecePublicKey = $INSTALL_CONFIG_DIR/$PUBKEY

[Peer]
McEliecePublicKey = $SERVER_PUBKEY_PATH
Endpoint = $EXT_SERVER_IP:$SERVER_PORT
AllowedIPs = $SERVER_IP
EOF

# generate the start-up scripts for server and 2 clients
gen_if_text() {
    IP=$1
    CMD=$(cat <<EOF
#!/bin/sh
# NOTE: this script is for illustration purpose only. For security, the script
# should not be used in production envrionment without modification.

PATH=/usr/bin:/usr/sbin:/bin:/sbin

if ! [ -x $WG ]; then
    echo "WireGuard command line tool not found at $WG. Aborting"
    exit 1
fi

sudo ip link add dev $IF type wireguard
sudo ip addr add $IP/$VPN_RANGE dev $IF
sudo ip link set $IF up
sudo $WG setconf $IF $INSTALL_CONFIG_DIR/$IF.conf
EOF
)
    echo "$CMD"
}

gen_if_text "$SERVER_IP" > "$SERVER_DIR/$SCRIPT"
gen_if_text "$CLIENT_IP.2" > "$CLIENT_DIR-1/$SCRIPT"
gen_if_text "$CLIENT_IP.3" > "$CLIENT_DIR-2/$SCRIPT"

chmod +x "$SERVER_DIR/$SCRIPT"
chmod +x "$CLIENT_DIR-1/$SCRIPT"
chmod +x "$CLIENT_DIR-2/$SCRIPT"

# copy public keys
cp "$SERVER_DIR/$PUBKEY" "$CLIENT_DIR-1/$SERVER_PUBKEY"
cp "$SERVER_DIR/$PUBKEY" "$CLIENT_DIR-2/$SERVER_PUBKEY"
cp "$CLIENT_DIR-1/$PUBKEY" "$SERVER_DIR/$CLIENT_PUBKEY-1"
cp "$CLIENT_DIR-2/$PUBKEY" "$SERVER_DIR/$CLIENT_PUBKEY-2"

# print info
cat <<EOF
Done. You now need to do the following:
    1. Copy the $SERVER_DIR folder onto the VPN server as $INSTALL_CONFIG_DIR
    2. Copy the $CLIENT_DIR-1 folder onto the 1st VPN client as $INSTALL_CONFIG_DIR
    3. Copy the $CLIENT_DIR-2 folder onto the 2nd VPN client as $INSTALL_CONFIG_DIR
    4. Run $INSTALL_CONFIG_DIR/$SCRIPT on each machine to start up WireGuard
EOF
