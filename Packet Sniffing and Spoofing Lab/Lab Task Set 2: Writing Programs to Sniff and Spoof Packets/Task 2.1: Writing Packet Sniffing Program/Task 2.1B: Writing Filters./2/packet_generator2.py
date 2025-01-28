#!/usr/bin/python3
from scapy.all import *
import random
a = IP()
a.dst = "1.2.3.4"
b = TCP()
b.dport = random.randint(10, 100)
pkt = a/b
send(pkt)