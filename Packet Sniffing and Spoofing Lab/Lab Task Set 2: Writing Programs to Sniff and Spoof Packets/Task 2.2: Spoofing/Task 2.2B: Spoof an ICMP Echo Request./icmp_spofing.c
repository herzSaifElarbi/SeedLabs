#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "header_struct.h"

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

int main() {
    int sd;
    struct sockaddr_in sin;
    char buffer[1024] = {0}; // Initialize buffer to zero
    struct ipheader *ip = (struct ipheader *)buffer;
    struct icmpheader *icmp = (struct icmpheader *)(buffer + sizeof(struct ipheader));

    // Create a raw socket
    sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sd < 0) {
        perror("socket() error");
        exit(-1);
    }

    // Set socket option to include the IP header
    int enable = 1;
    if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable)) < 0) {
        perror("setsockopt() error");
        close(sd);
        exit(-1);
    }

    // Fill in the IP header
    ip->iph_ihl = 5;  // IP header length in 32-bit words (5 * 4 = 20 bytes)
    ip->iph_ver = 4;  // IPv4
    ip->iph_tos = 0;  // Type of service
    ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader));  // Total length
    ip->iph_ident = htons(54321);  // Arbitrary ID
    ip->iph_offset = 0;  // No fragmentation
    ip->iph_ttl = 255;   // Time to Live
    ip->iph_protocol = IPPROTO_ICMP;  // ICMP protocol
    ip->iph_chksum = 0;  // Checksum will be calculated later
    ip->iph_sourceip.s_addr = inet_addr("10.0.2.6");  // Spoofed source IP
    ip->iph_destip.s_addr = inet_addr("10.0.2.5");    // Destination IP (e.g., Google DNS)

    // Calculate the IP header checksum
    ip->iph_chksum = checksum((unsigned short *)ip, sizeof(struct ipheader));

    // Fill in the ICMP header
    icmp->icmp_type = 8;  // ICMP Echo Request
    icmp->icmp_code = 0;  // Code for Echo Request
    icmp->icmp_id = htons(1234);  // Arbitrary ID
    icmp->icmp_seq = htons(1);    // Sequence number
    icmp->icmp_chksum = 0;         // Checksum will be calculated later

    // Calculate the ICMP checksum
    icmp->icmp_chksum = icmp_checksum((unsigned short *)icmp, sizeof(struct icmpheader));

    // Set the destination address for sendto()
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr("10.0.2.5");

    // Send the packet
    if (sendto(sd, buffer, ntohs(ip->iph_len), 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("sendto() error");
        close(sd);
        exit(-1);
    }

    printf("Spoofed ICMP Echo Request sent!\n");
    close(sd);
    return 0;
}