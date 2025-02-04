#!/usr/bin/python3
from scapy.all import *
def print_pkt(pkt):
    pkt.show()
subnet_filter = "net 128.230.0.0/16"

#we don't specify interface because only enp0s3 exists with loopback interface that it doesn't confuse us
pkt = sniff(filter=subnet_filter,prn=print_pkt)