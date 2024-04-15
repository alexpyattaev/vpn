ip link del veth_A
ip link del veth_B
ip netns del A
ip netns del B

ip netns add A
ip netns add B

alias IN_A="ip netns exec A"
alias IN_B="ip netns exec B"
# Virtual wire between namespaces
ip link add veth_A type veth peer name veth_B

ip link set dev veth_A netns A
IN_A ip link set lo up
IN_A ip link set veth_A up
IN_A ip a a 6.6.6.6/24 dev veth_A

ip link set dev veth_B netns B
IN_B ip link set lo up
IN_B ip link set veth_B up
IN_B ip a a 6.6.6.7/24 dev veth_B
