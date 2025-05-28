#include <pcap.h>
#include <stdio.h>
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    printf("Got a packet\n");
}
int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    //char filter_exp[] = "ip proto icmp";
    //char filter_exp[] = "icmp";
    ///////error
    char filter_exp[] = "tcp and dst portrange 10-100";
    //////
    bpf_u_int32 net;
        // Ouvrir l'interface réseau pour la capture
    //handle = pcap_open_live("eth3", BUFSIZ, 1, 1000, errbuf);
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device: %s\n", errbuf);
        return 1;
    }
        // Compiler l'expression du filtre en pseudo-code BPF
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
//gcc -o sniffer2 sniffer2.c -lpcap