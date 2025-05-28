#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/inet.h>  // for in_aton()
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Custom Firewall for SEED Lab");

// IP addresses in network byte order
#define MACHINE_A_IP in_aton("10.0.2.5")  
#define MACHINE_B_IP in_aton("10.0.2.6")
#define EXAMPLE_IP    in_aton("168.253.110.16")  
static struct nf_hook_ops nfho_in, nfho_out;

unsigned int incoming_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;

    if (!(ip_header = ip_hdr(skb))) return NF_ACCEPT;

    // Rule 2: Block incoming telnet from Machine B
    if (ip_header->saddr == MACHINE_B_IP && ip_header->protocol == IPPROTO_TCP) {
        tcp_header = tcp_hdr(skb);
        if (ntohs(tcp_header->dest) == 23) {
            printk(KERN_INFO "Firewall: Blocked incoming telnet from 10.0.2.6\n");
            return NF_DROP;
        }
    }

    // Additional Rule: Block SSH from Machine B
    if (ip_header->saddr == MACHINE_B_IP && ip_header->protocol == IPPROTO_TCP) {
        tcp_header = tcp_hdr(skb);
        if (ntohs(tcp_header->dest) == 22) {
            printk(KERN_INFO "Firewall: Blocked SSH from 10.0.2.6\n");
            return NF_DROP;
        }
    }

    return NF_ACCEPT;
}

unsigned int outgoing_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;

    if (!(ip_header = ip_hdr(skb))) return NF_ACCEPT;
    printk(KERN_INFO "OUTGOING PACKET TO: %pI4\n", &ip_header->daddr);
    // Rule 1: Block outgoing telnet to Machine B
    if (ip_header->daddr == MACHINE_B_IP && ip_header->protocol == IPPROTO_TCP) {
        tcp_header = tcp_hdr(skb);
        if (ntohs(tcp_header->dest) == 23) {
            printk(KERN_INFO "Firewall: Blocked outgoing telnet to 10.0.2.6\n");
            return NF_DROP;
        }
    }

    // Rule 3: Block access to example.com
    if (ip_header->daddr == EXAMPLE_IP && ip_header->protocol == IPPROTO_TCP) {
        tcp_header = tcp_hdr(skb);
        if (ntohs(tcp_header->dest) == 80 || ntohs(tcp_header->dest) == 443) {
            printk(KERN_INFO "Firewall: Blocked access to example.com\n");
            return NF_DROP;
        }
    }

    // Additional Rule: Block all ICMP
    if (ip_header->protocol == IPPROTO_ICMP) {
        printk(KERN_INFO "Firewall: Blocked ICMP packet\n");
        return NF_DROP;
    }

    return NF_ACCEPT;
}

static int __init fw_init(void) {
    // Incoming traffic hook
    nfho_in.hook = incoming_hook;
    nfho_in.hooknum = NF_INET_LOCAL_IN;
    nfho_in.pf = PF_INET;
    nfho_in.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&nfho_in);

    // Outgoing traffic hook
    nfho_out.hook = outgoing_hook;
    nfho_out.hooknum = NF_INET_LOCAL_OUT;
    nfho_out.pf = PF_INET;
    nfho_out.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&nfho_out);

    printk(KERN_INFO "Custom firewall loaded\n");
    return 0;
}

static void __exit fw_exit(void) {
    nf_unregister_hook(&nfho_in);
    nf_unregister_hook(&nfho_out);
    printk(KERN_INFO "Custom firewall unloaded\n");
}

module_init(fw_init);
module_exit(fw_exit);