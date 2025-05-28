#ifndef NETWORK_HEADERS_H
#define NETWORK_HEADERS_H
#include <netinet/in.h> // For `struct in_addr`
/* Define the Ethernet header structure */
typedef struct ethheader {
    u_char ether_dhost[6];       // Destination MAC address
    u_char ether_shost[6];       // Source MAC address
    u_short ether_type;          // Protocol type (IP, ARP, etc.)
} ethheader;
/* Define the IP header structure */
typedef struct ipheader {
    uint8_t iph_ihl : 4;    // IP header length (4 bits)
    uint8_t iph_ver : 4;    // IP version (4 bits)
    uint8_t iph_tos;        // Type of service (8 bits)
    uint16_t iph_len;       // IP Packet length (data + header) (16 bits)
    uint16_t iph_ident;     // Identification (16 bits)
    uint16_t iph_offset;   // Fragment offset (16 bits - includes flags)
    uint8_t iph_ttl;        // Time to Live (8 bits)
    uint8_t iph_protocol;   // Protocol type (8 bits)
    uint16_t iph_chksum;    // IP datagram checksum (16 bits)
    struct in_addr iph_sourceip; // Source IP address (32 bits)
    struct in_addr iph_destip;   // Destination IP address (32 bits)
} ipheader;
/* Define the TCP header structure */
typedef struct tcpheader {
    unsigned short th_sport;     // Source port
    unsigned short th_dport;     // Destination port
    unsigned int th_seq;         // Sequence number
    unsigned int th_ack;         // Acknowledgment number
    unsigned char th_off:4;      // Data offset
    unsigned char th_res:4;      // Reserved bits
    unsigned char th_flags;      // Control flags
    unsigned short th_win;       // Window size
    unsigned short th_sum;       // Checksum
    unsigned short th_urp;       // Urgent pointer
} tcpheader;
#endif // NETWORK_HEADERS_H
