#!/usr/bin/env bash

# Don't actually care about the return values of the variable assignments
#shellcheck disable=SC2155

# The fourth octet of the tunnel IP address that will be assigned to the server
# First 3 are based on the --tunnel-cidr parameter
SERVER_OCTET="1"

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

valid_cidr() {
  local CIDR=${1}

  # If it's formatted like a CIDR block
  if [[ ${CIDR} =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]
  then
    # Put each octet into an array...
    local CIDR_ARRAY[0]=$(echo "${CIDR}" | awk -F '.' '{ print $1 }')
    local CIDR_ARRAY[1]=$(echo "${CIDR}" | awk -F '.' '{ print $2 }')
    local CIDR_ARRAY[2]=$(echo "${CIDR}" | awk -F '.' '{ print $3 }')
    local CIDR_ARRAY[3]=$(echo "${CIDR}" | awk -F '.' '{ print $4 }')
    # ...Along with the netmask
    local CIDR_ARRAY[4]=$(echo "${CIDR}" | awk -F '/' '{ print $2 }')

    # Check the individual octets + netmask for validity
    # Are the octets between 0 and 255?
    # Is the netmask between 0 and 32?
    if [[ ${CIDR_ARRAY[0]} -le 255 ]] && [[ ${CIDR_ARRAY[0]} -ge 0 ]] \
      && [[ ${CIDR_ARRAY[1]} -le 255 ]] && [[ ${CIDR_ARRAY[1]} -ge 0 ]] \
      && [[ ${CIDR_ARRAY[2]} -le 255 ]] && [[ ${CIDR_ARRAY[2]} -ge 0 ]] \
      && [[ ${CIDR_ARRAY[3]} -le 255 ]] && [[ ${CIDR_ARRAY[3]} -ge 0 ]] \
      && [[ ${CIDR_ARRAY[4]} -le 32 ]] && [[ ${CIDR_ARRAY[4]} -ge 0 ]]
    then
      return 0
    else
      return 1
    fi
  else
    return 1
  fi
}

configure_new_server() {
  local TUNNEL_CIDR=$1
  local SERVER_OCTET=$2
  local SERVER_PORT=$3
  local FORCE=$4

  # Build the servers IP address
  local TUNNEL_NETMASK=$(echo "${TUNNEL_CIDR}" | awk -F '/' '{ print $2 }' | tr -d '[:space:]')
  local TUNNEL_OCTETS=$(echo "${TUNNEL_CIDR}" | awk -F '.' '{ print $1"."$2"."$3"." }' | tr -d '[:space:]')
  local SERVER_CIDR="${TUNNEL_OCTETS}${SERVER_OCTET}/${TUNNEL_NETMASK}"

  # Find our default gateway
  local GATEWAY_INTERFACE=$(route | grep default | awk '{ print $8 }' | tr -d '[:space:]')

  # Generate a keypair for the server to use
  local SERVER_PRIVATE_KEY=$(wg genkey)
  local SERVER_PUBLIC_KEY=$(echo "${SERVER_PRIVATE_KEY}" | wg pubkey)

  ## NEW SERVER
  # If there is an existing config, and the "--force" flag isn't set
  if [ -e /etc/wireguard/wg0.conf ] && [[ ${FORCE} -ne 1 ]]
  then
    echo "There is already an existing config. Exiting..."
    exit 1
  else 
    # If the config exists but the "--force" flag was set, back up the existing config
    if [ -e /etc/wireguard/wg0.conf ] && [[ ${FORCE} -eq 1 ]]
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

  chmod 600 /etc/wireguard/wg0.conf

  # Check if sysctl is configured properly for traffic forwarding
  if [ -e /etc/sysctl.d/wireguard.conf ]
  then
    # Get the config
    local SYSCTL_CONFIG=$(cat /etc/sysctl.d/wireguard.conf)
    # Check the config file for our required values. If theyre missing, append them to the file
    if ! ( (echo "${SYSCTL_CONFIG}" | grep -q "net.ipv4.ip_forward=1") && (echo "${SYSCTL_CONFIG}" | grep -q "net.ipv6.conf.all.forwarding=1") )
    then
cat << EOF >> /etc/sysctl.d/wireguard.conf
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
EOF
    sysctl --system &> /dev/null
    fi
  else
  # If the file doesn't exist, create it
cat << EOF > /etc/sysctl.d/wireguard.conf
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
EOF
    sysctl --system &> /dev/null
  fi
  
  # Ensure there is no server currently running
  wg-quick down /etc/wireguard/wg0.conf &> /dev/null
  echo "Starting VPN server..."
  wg-quick up /etc/wireguard/wg0.conf &> /dev/null
  echo "Setting VPN server to start on boot..."
  systemctl enable wg-quick@wg0 &> /dev/null

}

add_client() {
  local NOW=$(date +%Y%m%d%H%M%S)
  # Generate a keypair for the server to use
  local CLIENT_PRIVATE_KEY=$(wg genkey)
  local CLIENT_PUBLIC_KEY=$(echo "${CLIENT_PRIVATE_KEY}" | wg pubkey)

  # Get information about the server config
  local TUNNEL_CIDR=$(sed -n '/\[Interface\]/,/\[Peer\]/p' /etc/wireguard/wg0.conf | grep "PreUp" | awk '{ print $9 }' | tr -d '[:space:]')
  local TUNNEL_NETMASK=$(echo "${TUNNEL_CIDR}" | awk -F '/' '{ print $2 }' | tr -d '[:space:]')
  local TUNNEL_OCTETS=$(echo "${TUNNEL_CIDR}" | awk -F '.' '{ print $1"."$2"."$3"." }' | tr -d '[:space:]')
  local SERVER_CIDR=$(sed -n '/\[Interface\]/,/\[Peer\]/p' /etc/wireguard/wg0.conf | grep "Address" | awk -F ' = ' '{ print $2 }' | tr -d '[:space:]')
  local SERVER_PUBLIC_KEY=$(sed -n '/\[Interface\]/,/\[Peer\]/p' /etc/wireguard/wg0.conf | grep "PublicKey" | awk -F ' = ' '{ print $2 }' | tr -d '[:space:]')
  local SERVER_PORT=$(sed -n '/\[Interface\]/,/\[Peer\]/p' /etc/wireguard/wg0.conf | grep "ListenPort" | awk -F ' = ' '{ print $2 }' | tr -d '[:space:]')
  local SERVER_PUBLIC_IP=$(curl -s ipv4.icanhazip.com)

  # Find the highest client address in the config
  local CURRENT_HIGHEST_OCTET=$(grep -o "${TUNNEL_OCTETS}.*" /etc/wireguard/wg0.conf | awk '{ print $1 }' | sort -u | tail -n 1 | awk -F '/' '{ print $1 }' | awk -F '.' '{ print $4 }')
  # Build the next one
  local NEW_HIGHEST_OCTET=$((CURRENT_HIGHEST_OCTET+1))
  # Turn it into a CIDR format address
  local CLIENT_CIDR=${TUNNEL_OCTETS}${NEW_HIGHEST_OCTET}/${TUNNEL_NETMASK}

# ADD NEW CLIENT TO SERVER
cat << EOF >> /etc/wireguard/wg0.conf
[Peer]
# Just to keep track of our clients and prevent IP conflicts
# ClientAddress = ${CLIENT_CIDR}
# Public key of the client
PublicKey = ${CLIENT_PUBLIC_KEY}
# IPs to send through the tunnel
AllowedIPs = ${TUNNEL_CIDR}

EOF

# Generate client config
cat << EOF >> "${HOME}/client.${NOW}.conf"
[Interface]
PrivateKey = ${CLIENT_PRIVATE_KEY}
# Public key not needed for our side of the tunnel, just here for safe keeping
#PublicKey = ${CLIENT_PUBLIC_KEY}
# The local address of the client, within the tunnel
Address = ${CLIENT_CIDR}
# DNS servers that we know will be accessible through the tunnel
# Forcing DNS servers prevents DNS leaks
DNS = 1.1.1.1, 1.0.0.1

[Peer]
# Public key of the server
PublicKey = ${SERVER_PUBLIC_KEY}
# IPs to send through the tunnel - This sends everything, for maximum privacy
AllowedIPs = 0.0.0.0/0
Endpoint = ${SERVER_PUBLIC_IP}:${SERVER_PORT}
EOF

  # Ensure there is no server currently running
  echo "Restarting VPN server..."
  wg-quick down /etc/wireguard/wg0.conf &> /dev/null
  wg-quick up /etc/wireguard/wg0.conf &> /dev/null

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
      new-server)
        NEW_SERVER=1
        ;;
      new-client)
        NEW_CLIENT=1
        ;;
      *)
        usage
        ;;
      esac
      shift
  done
fi

#TUNNEL_CIDR="10.69.0.0/24"
#SERVER_PORT=51280

if [[ ${EUID} -ne 0 ]]
then
  echo "This script must be run as root"
  usage
fi

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
if ! (command -v wg &> /dev/null)
then
  echo "Wireguard installation not found, installing..."
  apt install -y software-properties-common &> /dev/null
  apt update &> /dev/null
  apt-add-repository -y ppa:wireguard/wireguard &> /dev/null
  apt install -y -q wireguard &> /dev/null
  echo "Wireguard installed."
fi

if [[ ${NEW_SERVER} -eq 1 ]]
then
  # If the CIDR range doesn't validate, or was not given
  if [ -z "${TUNNEL_CIDR}" ] || ! (valid_cidr "${TUNNEL_CIDR}")
  then
    echo "No valid CIDR range specified"
    usage
  elif [ -z "${SERVER_PORT}" ]
  then
    echo "No valid port number specified"
    usage
  else
    echo "Setting up new Wireguard server..."
    configure_new_server "${TUNNEL_CIDR}" "${SERVER_OCTET}" "${SERVER_PORT}" "${FORCE}"
    echo "Server setup complete!"
  fi
elif [[ ${NEW_CLIENT} -eq 1 ]]
then
  echo "Adding new client..."
  add_client
else
  usage
fi
