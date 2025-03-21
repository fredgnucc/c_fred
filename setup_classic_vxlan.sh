#!/bin/bash

set -e

# Network config
NS_NAME="router"
VETH_HOST="veth-host"
VETH_CONT="veth-router"
IP_CONT="192.168.150.1/24"
VXLAN_IF="vxlan0"
VXLAN_LOCAL="10.240.0.38"
VXLAN_REMOTE="10.240.0.39"

BRIDGE="br0"

echo "🌐 Creating network namespace..."
sudo ip netns add $NS_NAME || echo "Namespace $NS_NAME already exists."

echo "🔌 Creating veth pair..."
sudo ip link add $VETH_HOST type veth peer name $VETH_CONT

echo "📦 Moving container end of veth into namespace..."
sudo ip link set $VETH_CONT netns $NS_NAME

echo "🏠 Configuring host veth interface..."
#sudo ip addr add $IP_HOST dev $VETH_HOST
sudo ip link set $VETH_HOST up

echo "📦 Configuring container side..."
sudo ip netns exec $NS_NAME ip addr add $IP_CONT dev $VETH_CONT
sudo ip netns exec $NS_NAME ip link set $VETH_CONT up
sudo ip netns exec $NS_NAME ip link set lo up

echo "🌉 Creating VXLAN interface..."
sudo ip link add $VXLAN_IF type vxlan id 100 dstport 4789 dev ens192 remote $VXLAN_REMOTE local $VXLAN_LOCAL
sudo ip link set $VXLAN_IF up

echo "🔗 Creating bridge $BRIDGE and connecting interfaces..."
sudo ip link add $BRIDGE type bridge || true
sudo ip link set $BRIDGE up

sudo ip link set $VETH_HOST master $BRIDGE
sudo ip link set $VXLAN_IF master $BRIDGE

echo "✅ Setup complete on host with IP $VXLAN_LOCAL"
