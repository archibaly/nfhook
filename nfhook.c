#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>

MODULE_LICENSE("GPL");

static struct nf_hook_ops nfho;

static unsigned int hook_func(const struct nf_hook_ops *ops,
							  struct sk_buff *skb,
							  const struct net_device *in,
							  const struct net_device *out,
							  int (*okfn) (struct sk_buff *))
{
#ifdef BASE_TEST
	return NF_DROP;
#endif
#ifdef INTF_TEST
	if (strcmp(in->name, "eth0") == 0)
		return NF_DROP;
#endif
#ifdef ADDR_TEST
	static unsigned char *drop_ip = "/x0a/x08/x50/x6c";
	struct sk_buff *sk = *skb;

	if (sk->nh.iph->saddr == *(unsigned int *)drop_ip)
		return NF_DROP;
#endif

#ifdef PORT_TEST
	unsigned char *deny_port = "/x00/x19";	/* port 25 */
	struct tcphdr *th;

	if (!skb)
		return NF_ACCEPT;
	if (!(skb->nh.iph))
		return NF_ACCEPT;
	if (skb->nh.iph->protocol != IPPROTO_TCP)
		return NF_ACCEPT;
	th = (struct tcphdr *)(skb->data + (skb->nh.iph->ihl * 4));

	if ((th->dest) == *(unsigned short *)deny_port)
		return NF_DROP;
#endif
	return NF_ACCEPT;
}

static int __init init_nfhook(void)
{
	nfho.hook = hook_func;
	nfho.hooknum = NF_INET_PRE_ROUTING;
	nfho.pf = PF_INET;
	nfho.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&nfho);
	return 0;
}

static void __exit exit_nfhook(void)
{
	nf_unregister_hook(&nfho);
}

module_init(init_nfhook);
module_exit(exit_nfhook);
