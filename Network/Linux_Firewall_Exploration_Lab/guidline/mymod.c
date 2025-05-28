#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
/* This is the structure we shall use to register our function */
static struct nf_hook_ops nfho;
/* This is the hook function itself */
unsigned int hook_func(void *priv, struct sk_buff *skb,
    const struct nf_hook_state *state)
{
/* This is where you can inspect the packet contained in
the structure pointed by skb, and decide whether to accept
or drop it. You can even modify the packet */
// In this example, we simply drop all packets
    return NF_DROP; /* Drop ALL packets */
}
/* Initialization routine */
int init_module()
{ /* Fill in our hook structure */
    nfho.hook = hook_func; /* Handler function */
    nfho.hooknum = NF_INET_PRE_ROUTING; /* First hook for IPv4 */
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST; /* Make our function first */
    nf_register_hook(&nfho);
    return 0;
}
/* Cleanup routine */
void cleanup_module()
{
    nf_unregister_hook(&nfho);
}