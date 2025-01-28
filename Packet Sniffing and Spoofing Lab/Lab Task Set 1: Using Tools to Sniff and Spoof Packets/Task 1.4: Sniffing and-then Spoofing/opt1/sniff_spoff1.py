#!/usr/bin/python3
from scapy.all import *
def spoof_pkt(pkt):
    if ICMP in pkt and pkt[ICMP].type == 8:
        print("*********ICMP***********")
        print("sniffed:",pkt[IP].src, " => ", pkt[IP].dst)
        ip = IP(src=pkt[IP].dst, dst=pkt[IP].src, ihl=pkt[IP].ihl)
        icmp = ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)
        if Raw in pkt:
            data = pkt[Raw].load
            newpkt = ip/icmp/data
        else:
            newpkt = ip/icmp
        print("spoffed", newpkt[IP].src, " => ", newpkt[IP].dst)
        send(newpkt, verbose=0)

sniff(filter='icmp', prn=spoof_pkt, count = 5)