#!/usr/bin/python3
from scapy.all import *
a = IP()
a.src = "10.0.2.100" #10.0.2.0/24
a.dst = "192.168.60.5"
b = ICMP()
pkt = a/b
send(pkt)