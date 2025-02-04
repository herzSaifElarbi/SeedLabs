#!/usr/bin/python3
from scapy.all import *
a = IP()
a.src = "1.2.3.4" #1.2.3.4.
a.dst = "192.168.60.5"
b = ICMP()
pkt = a/b
send(pkt)