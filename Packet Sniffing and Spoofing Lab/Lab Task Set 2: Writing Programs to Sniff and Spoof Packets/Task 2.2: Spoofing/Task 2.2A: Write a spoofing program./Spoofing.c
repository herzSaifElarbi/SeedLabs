#include <pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "header_struct.h"
// Function to calculate the checksum for the IP header
//inverse(sum 4 bytes)
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
int main() {
    int sd;
    struct sockaddr_in sin;
    char buffer[1024];// You can change the buffer size
    struct ipheader *ip = (struct ipheader *)buffer;
    struct udpheader *udp = (struct udpheader *)(buffer + sizeof(struct ipheader));
    // Create a raw socket
    sd = socket(AF_INET,SOCK_RAW,IPPROTO_RAW);
    if(sd < 0){
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
    //filling neccissary fields ip header
    // Fill in the IP header
    ip->iph_ihl = 5;//20 is standard without option so 20/4 = 5
    ip->iph_ver = 4;
    ip->iph_tos = 0;
    ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct udpheader));    
    ip->iph_ident = htons(54321);  // Arbitrary ID
    ip->iph_offset = 0;
    ip->iph_ttl = 255;
    ip->iph_protocol = IPPROTO_UDP;  // UDP protocol
    ip->iph_chksum = 0;  // Checksum will be calculated later
    ip->iph_sourceip.s_addr = inet_addr("10.0.2.6");  // Spoofed source IP
    ip->iph_destip.s_addr = inet_addr("10.0.2.5");    // Destination IP
    ip->iph_chksum = checksum((unsigned short *)buffer, sizeof(struct ipheader));
    udp->udp_sport = htons(1234);  // Source port
    udp->udp_dport = htons(5678);    // Destination port
    udp->udp_ulen = htons(sizeof(struct udpheader));
    udp->udp_sum = 0;  // UDP checksum (optional)
    sin.sin_family = AF_INET;
    sin.sin_port = htons(5678);
    sin.sin_addr.s_addr = inet_addr("10.0.2.5");
    /* Send out the IP packet.
    * ip_len is the actual size of the packet. */
    if(sendto(sd,buffer,ntohs(ip->iph_len),0, (struct sockaddr*)&sin,sizeof(sin)) < 0) {
        perror("sendto()error"); 
        close(sd);
        exit(-1);
    }
    printf("Spoofed packet sent!\n");
    close(sd);
    return 0;
}