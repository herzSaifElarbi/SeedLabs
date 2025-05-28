#include <pcap.h>
#include <stdio.h>
#include "header_struct.h"
#include <arpa/inet.h>    // For inet_ntoa
#include <ctype.h>        // For isprint()
/* Function to filter and print only relevant ASCII characters */
void print_payload_ascii(const u_char *payload, int length) {
    for (int i = 0; i < length; i++) {
        if (isprint(payload[i])) { 
            putchar(payload[i]); // Print printable characters
        } else {
            putchar('.'); // Replace non-printable characters with dots
        }
    }
    printf("\n____________________________________________\n");
}
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;
    struct ipheader *ip;
    int ip_header_length;
    struct tcpheader *tcp;
    int tcp_header_length;
    u_char *payload;
    int payload_length;
    if (ntohs(eth->ether_type) == 0x0800) {
        //0x0800 for IP
        struct ipheader *ip = (struct ipheader *)(packet + 14);
        //14 is size of ethernet header
        if(ip->iph_protocol == 6){
            //6 for tcp protocol
            ip_header_length = ip->iph_ihl * 4; // IP header length in bytes
            tcp = (struct tcpheader *)((u_char *)ip + ip_header_length);
            tcp_header_length = tcp->th_off * 4; // TCP header length in bytes
            payload = (u_char *)((u_char *)tcp + tcp_header_length); // Locate payload
            payload_length = ntohs(ip->iph_len) - (ip_header_length + tcp_header_length); // Calculate payload size
            if (payload_length > 0) {
                print_payload_ascii(payload , payload_length);
            }
        }
    }
}
int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    //char filter_exp[] = "ip proto icmp";
    char filter_exp[] = "ip";
    bpf_u_int32 net;
    //handle = pcap_open_live("eth3", BUFSIZ, 1, 1000, errbuf);
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device: %s\n", errbuf);
        return 1;
    }
    // Step 2: Compile filter_exp into BPF pseudo-code
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(handle));
        return 1;
    }
    // Set the filter
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
        return 1;
    }
    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);
    // Close the handle
    pcap_close(handle);
    return 0;
}
//gcc -o Sniffing_Passwords Sniffing_Passwords.c -lpcap
