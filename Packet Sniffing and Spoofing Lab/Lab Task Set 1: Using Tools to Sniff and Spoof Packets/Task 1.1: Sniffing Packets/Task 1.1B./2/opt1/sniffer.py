#!/usr/bin/python3
from scapy.all import *
def print_pkt(pkt):
    pkt.show()

source_ip  = "10.0.2.5"
destination_port = "23"
bpf_filter = "tcp and src host " + source_ip + " and dst port " + destination_port

#we don't specify interface because only enp0s3 exists with loopback interface that it doesn't confuse us
pkt = sniff(filter=bpf_filter,prn=print_pkt)