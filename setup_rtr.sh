#!/bin/bash
set -e

# Define namespaces and interfaces
ROUTER_NS="router"
NS1="ns1"
NS2="ns2"

# Define Bridges for two networks
BRIDGE_A="br100"
BRIDGE_B="br200"

# Define IP addresses for each network
# Network A (br100): 192.168.151.0/24
#   Router interface: 192.168.151.254/24, ns1: 192.168.151.1/24
# Network B (br200): 192.168.152.0/24
#   Router interface: 192.168.152.254/24, ns2: 192.168.152.1/24
ROUTER_A_IP="192.168.151.254/24"
NS1_IP="192.168.151.1/24"

ROUTER_B_IP="192.168.152.254/24"
NS2_IP="192.168.152.1/24"

echo "==> Creating router namespace..."
sudo ip netns add $ROUTER_NS || echo "Namespace $ROUTER_NS already exists."

echo "==> Creating container namespaces ns1 and ns2..."
sudo ip netns add $NS1 || echo "Namespace $NS1 already exists."
sudo ip netns add $NS2 || echo "Namespace $NS2 already exists."

echo "==> Creating bridges for Network A and Network B..."
sudo ip link add name $BRIDGE_A type bridge 2>/dev/null || echo "Bridge $BRIDGE_A exists."
sudo ip link add name $BRIDGE_B type bridge 2>/dev/null || echo "Bridge $BRIDGE_B exists."
sudo ip link set $BRIDGE_A up
sudo ip link set $BRIDGE_B up

# Connect Router to Network A
echo "==> Connecting router to Network A (br100)..."
sudo ip link add veth-A type veth peer name veth-routerA
sudo ip link set veth-A master $BRIDGE_A
sudo ip link set veth-A up
sudo ip link set veth-routerA netns $ROUTER_NS
sudo ip netns exec $ROUTER_NS ip addr add $ROUTER_A_IP dev veth-routerA
sudo ip netns exec $ROUTER_NS ip link set veth-routerA up

# Connect Router to Network B
echo "==> Connecting router to Network B (br200)..."
sudo ip link add veth-B type veth peer name veth-routerB
sudo ip link set veth-B master $BRIDGE_B
sudo ip link set veth-B up
sudo ip link set veth-routerB netns $ROUTER_NS
sudo ip netns exec $ROUTER_NS ip addr add $ROUTER_B_IP dev veth-routerB
sudo ip netns exec $ROUTER_NS ip link set veth-routerB up

# Enable IP forwarding in the router namespace
echo "==> Enabling IP forwarding in router namespace..."
sudo ip netns exec $ROUTER_NS sysctl -w net.ipv4.ip_forward=1

# Connect ns1 to Network A (br100)
echo "==> Connecting ns1 to Network A (br100)..."
sudo ip link add veth-host-ns1 type veth peer name veth-ns1
sudo ip link set veth-host-ns1 master $BRIDGE_A
sudo ip link set veth-host-ns1 up
sudo ip link set veth-ns1 netns $NS1
sudo ip netns exec $NS1 ip addr add $NS1_IP dev veth-ns1
sudo ip netns exec $NS1 ip link set veth-ns1 up
sudo ip netns exec $NS1 ip link set lo up
# Set ns1 default route via router
sudo ip netns exec $NS1 ip route add default via 192.168.151.254

# Connect ns2 to Network B (br200)
echo "==> Connecting ns2 to Network B (br200)..."
sudo ip link add veth-host-ns2 type veth peer name veth-ns2
sudo ip link set veth-host-ns2 master $BRIDGE_B
sudo ip link set veth-host-ns2 up
sudo ip link set veth-ns2 netns $NS2
sudo ip netns exec $NS2 ip addr add $NS2_IP dev veth-ns2
sudo ip netns exec $NS2 ip link set veth-ns2 up
sudo ip netns exec $NS2 ip link set lo up
# Set ns2 default route via router
sudo ip netns exec $NS2 ip route add default via 192.168.152.254

echo "==> Super build complete!"

echo "Router namespace ($ROUTER_NS) interfaces:"
sudo ip netns exec $ROUTER_NS ip addr show

echo "Namespace $NS1 interfaces:"
sudo ip netns exec $NS1 ip addr show

echo "Namespace $NS2 interfaces:"
sudo ip netns exec $NS2 ip addr show
