#!/usr/bin/python3
from scapy.all import *
def tracer(dst, max_hops = 30):
    a = IP()
    b = ICMP()
    a.dst = dst
    for ttl in range(1, max_hops + 1):
        a.ttl = ttl
        pkt = a/b
        reply = sr1(pkt, timeout = 2)
        if reply is None:
            print(ttl, ": Request timed out")
            #type = 8 is for request
        elif reply.type == 0:
            # Echo reply means we reached the destination
            print(ttl, ":", reply.src)
            print("Destination Reached")
            break
        elif reply.type == 11:
            #codes 0, 1 ttl got dropped, the other for fragmentation
            # Time Exceeded (droped packet)
            print(ttl, ":", reply.src)
        else:
            print(ttl, ": Unexpected reply type: ", reply.type)
tracer("8.8.8.8")