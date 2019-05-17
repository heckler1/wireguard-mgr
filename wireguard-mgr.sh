#!/usr/bin/env bash

# Don't actually care about the return values of the variable assignments
#shellcheck disable=SC2155

# The fourth octet of the tunnel IP address that will be assigned to the server
# First 3 are based on the --tunnel-cidr parameter
SERVER_OCTET="1"

# TODO
# Add CIDR validation function

#############
# VARIABLES #
#############

# Set our path, just in case
PATH=${PATH}:/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin

# Get the name of the script
APP_NAME=$(basename "${0}")


#############
# FUNCTIONS #
#############

usage() {
  echo "Usage: ${APP_NAME} new-server --tunnel-cidr <CIDR_RANGE> --server-port <SERVER_PORT> [--force]"
  echo "Usage: ${APP_NAME} new-client"
  exit 1
}

configure_new_server() {
  local TUNNEL_CIDR=$1
  local SERVER_OCTET=$2
  local SERVER_PORT=$3
  local FORCE=$4

  # Build the servers IP address
  local TUNNEL_NETMASK=$(echo "${TUNNEL_CIDR}" | awk -F '/' '{ print $2 }')
  local TUNNEL_OCTETS=$(echo "${TUNNEL_CIDR}" | awk -F '.' '{ print $1"."$2"."$3"." }')
  local SERVER_CIDR="${TUNNEL_OCTETS}${SERVER_OCTET}/${TUNNEL_NETMASK}"

  # Find our default gateway
  local GATEWAY_INTERFACE=$(route | grep default | awk '{ print $8 }')

  # Generate a keypair for the server to use
  local SERVER_PRIVATE_KEY=$(wg genkey)
  local SERVER_PUBLIC_KEY=$(echo "${PRIVATE_KEY}" | wg pubkey)

  ## NEW SERVER
  # If there is an existing config, and the "--force" flag isn't set
  if [ -e /etc/wireguard/wg0.conf ] && [ "${FORCE}" -ne "1" ]
  then
    echo "There is already an existing config. Exiting..."
    exit 1
  else 
    # If the config exists but the "--force" flag was set, back up the existing config
    if [ -e /etc/wireguard/wg0.conf ] && [ "${FORCE}" -eq 1 ]
    then
      mv "/etc/wireguard/wg0.conf" "/etc/wireguard/wg0.conf.$(date).bak"
    fi
  # Otherwise, write a new config
cat << EOF > /etc/wireguard/wg0.conf
[Interface]
# Private key on the server
PrivateKey = ${SERVER_PRIVATE_KEY}
# Public key of the server, stored here for safe keeping
# PublicKey = ${SERVER_PUBLIC_KEY}
# The local address of the server, within the tunnel
Address = ${SERVER_CIDR}
# Port the server will listen on
ListenPort = ${SERVER_PORT}
# Install NAT rules for client internet access
PreUp = iptables -t nat -A POSTROUTING -s ${TUNNEL_CIDR} -o ${GATEWAY_INTERFACE} -j MASQUERADE
PostDown = iptables -t nat -D POSTROUTING -s ${TUNNEL_CIDR} -o ${GATEWAY_INTERFACE} -j MASQUERADE

EOF
  fi


  # Check if sysctl is configured properly for traffic forwarding
  if [ -e /etc/sysctl.d/wireguard.conf ]
  then
    # Get the config
    local SYSCTL_CONFIG=$(cat /etc/sysctl.d/wireguard.conf)
    # Check the config file for our required values. If theyre missing, append them to the file
    if ! (echo "${SYSCTL_CONFIG}" | grep -q "net.ipv4.ip_forward=1") && (echo "${SYSCTL_CONFIG}" | grep -q "net.ipv6.conf.all.forwarding=1")
    then
cat << EOF >> /etc/sysctl.d/wireguard.conf
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
EOF
    sysctl -p
    fi
  else
  # If the file doesn't exist, create it
cat << EOF > /etc/sysctl.d/wireguard.conf
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
EOF
    sysctl -p
  fi

}

add_client() {
  local NOW=$(date)
  # Generate a keypair for the server to use
  local CLIENT_PRIVATE_KEY=$(wg genkey)
  local CLIENT_PUBLIC_KEY=$(echo "${PRIVATE_KEY}" | wg pubkey)

  # Get information about the server config
  local TUNNEL_CIDR=$(sed -n '/\[Interface\]/,/\[Peer\]/p' /etc/wireguard/wg0.conf | grep "PreUp" | awk -F '=' '{ print $9 }')
  local SERVER_ADDRESS=$(sed -n '/\[Interface\]/,/\[Peer\]/p' /etc/wireguard/wg0.conf | grep "Address" | awk -F '=' '{ print $2 }')
  local SERVER_PUBLIC_KEY=$(sed -n '/\[Interface\]/,/\[Peer\]/p' /etc/wireguard/wg0.conf | grep "PublicKey" | awk -F '=' '{ print $2 }')
  local SERVER_PORT=$(sed -n '/\[Interface\]/,/\[Peer\]/p' /etc/wireguard/wg0.conf | grep "ListenPort" | awk -F '=' '{ print $2 }')
  local SERVER_PUBLIC_IP=$(curl ipv4.icanhazip.com)

  #
  # TODO
  #
  # Find the highest client address
  # Build the next one

# ADD NEW CLIENT TO SERVER
cat << EOF >> /etc/wireguard/wg0.conf
[Peer]
# Public key of the client
PublicKey = ${CLIENT_PUBLIC_KEY}
# IPs to send through the tunnel
AllowedIPs = ${TUNNEL_CIDR}

EOF



# Generate client config
cat << EOF >> "${HOME}/client.${NOW}conf"
[Interface]
PrivateKey = ${CLIENT_PRIVATE_KEY}
# Public key not needed for our side of the tunnel, just here for safe keeping
#PublicKey = ${CLIENT_PUBLIC_KEY}
# The local address of the server, within the tunnel
Address = ${CLIENT_ADDRESS}
# DNS servers that we know will be accessible through the tunnel
# Only uncomment this if you can ping across the tunnel, but are unable to access websites
# DNS = 1.1.1.1, 1.0.0.1

[Peer]
# Public key of the server
PublicKey = ${SERVER_PUBLIC_KEY}
# IPs to send through the tunnel - This allows everything but local traffic
AllowedIPs = 0.0.0.0/5, 8.0.0.0/7, 11.0.0.0/8, 12.0.0.0/6, 16.0.0.0/4, 32.0.0.0/3, 64.0.0.0/2, 128.0.0.0/3, 160.0.0.0/5, 168.0.0.0/6, 172.0.0.0/12, 172.32.0.0/11, 172.64.0.0/10, 172.128.0.0/9, 173.0.0.0/8, 174.0.0.0/7, 176.0.0.0/4, 192.0.0.0/9, 192.128.0.0/11, 192.160.0.0/13, 192.169.0.0/16, 192.170.0.0/15, 192.172.0.0/14, 192.176.0.0/12, 192.192.0.0/10, 193.0.0.0/8, 194.0.0.0/7, 196.0.0.0/6, 200.0.0.0/5, 208.0.0.0/4, 1.1.1.1/32, 1.0.0.1/32
Endpoint = ${SERVER_PUBLIC_IP}:${SERVER_PORT}
EOF

  echo "Your new client config has been output to ${HOME}/client.${NOW}.conf"
}

###############
# SCRIPT BODY #
###############

# Evaluate all of our options
# Options can be in any order in the command
if [ ${#} -eq 0 ]
# If there are no options
then
  usage
else
  while [ ${#} -gt 0 ]
  # If there are some options
  do
    case "${1}" in
      --tunnel-cidr)
        TUNNEL_CIDR=${2}
        shift
        ;;
      --server-port)
        SERVER_PORT=${2}
        shift
        ;;
      --force)
        FORCE=1
        ;;
      --new-server)
        NEW_SERVER=1
        ;;
      --new-client)
        NEW_CLIENT=1
        ;;
      *)
        usage
        ;;
      esac
      shift
  done
fi

TUNNEL_CIDR="10.69.0.0/24"
SERVER_PORT=51280


# If this distro has an lsb-release file
if [ -e /etc/lsb-release ]
then
  LSB_RELEASE=$(cat /etc/lsb-release)
  # Confirm we're running Ubuntu 18.04
  if ! (echo "${LSB_RELEASE}" | grep "Ubuntu" | grep "18.04" &> /dev/null)
  then
    echo "This script only works on Ubuntu 18.04"
  fi
else
  echo "This script only works on Ubuntu 18.04"
fi

# Check if WireGuard is installed:
if ! (apt list wireguard &> /dev/null)
then
  add-apt-repository -y ppa:wireguard/wireguard
  apt install -y -q wireguard
fi

if [ "${NEW_SERVER}" -eq "1" ]
then
  if [ -z ${TUNNEL_CIDR} ]
  then
    echo "No valid CIDR range specified"
    usage
  elif [ -z ${SERVER_PORT} ]
  then
    echo "No valid port number specified"
    usage
  fi
  configure_new_server "${TUNNEL_CIDR}" "${SERVER_OCTET}" "${SERVER_PORT}" "${FORCE}"
elif [ "${NEW_CLIENT}" -eq "1" ]
then
  add_client
fi
