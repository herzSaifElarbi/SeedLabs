#!/usr/bin/python3
from scapy.all import *
a = IP()
a.src = "10.0.2.5"
a.dst = "10.0.2.6"
b = TCP()
b.dport = 23
pkt = a/b
send(pkt)

