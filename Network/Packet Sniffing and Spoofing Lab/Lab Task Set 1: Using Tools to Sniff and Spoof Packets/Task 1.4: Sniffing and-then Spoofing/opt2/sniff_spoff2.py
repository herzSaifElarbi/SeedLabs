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
    elif ARP in pkt and pkt[ARP].op == 1:
        print("*********ARP***********")
        print("sniffed:", pkt[ARP].psrc, " => ", pkt[ARP].pdst)
        arp_reply = ARP(pdst=pkt[ARP].psrc, psrc=pkt[ARP].pdst, op=2, hwdst=pkt[ARP].hwsrc, hwsrc="08:00:27:46:8a:e7")
        send(arp_reply, verbose=0)

sniff(filter='arp || icmp', prn=spoof_pkt)