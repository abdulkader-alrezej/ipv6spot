#!/bin/sh
#
ip link add dev dw type veth peer dwpeer
ip addr add dev dwpeer 2002:db9::2/64
ip addr add dev dwpeer 2002:db7::2/64
ip addr add dev dwpeer 2002:db6::2/64
ip link set dev dw up
ip link set dev dwpeer up
#
ip link add dev du type veth peer dupeer
ip addr add dev dupeer 2002:db4::2/64
ip link set dev du up
ip link set dev dupeer up
