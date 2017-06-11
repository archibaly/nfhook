#include <linux/module.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>

MODULE_LICENSE("GPL");

#define PROC_MAX_SIZE	32

static char proc_buf[PROC_MAX_SIZE];
static int ip_drop = 0;
struct proc_dir_entry *proc_ip_drop;

static struct nf_hook_ops nfho;

static unsigned int hook_func(const struct nf_hook_ops *ops,
							  struct sk_buff *skb,
							  const struct net_device *in,
							  const struct net_device *out,
							  int (*okfn) (struct sk_buff *))
{
	if (ip_drop)
		return NF_DROP;
	else
		return NF_ACCEPT;
}

static ssize_t proc_write(struct file *fp, const char *buf, size_t len, loff_t *off)
{
	if (len > PROC_MAX_SIZE)
		return -EFAULT;
	if (copy_from_user(proc_buf, buf, len))
		return -EFAULT;
	ip_drop = simple_strtoul(proc_buf, NULL, 10);
	return len;
}

static ssize_t proc_read(struct file *fp, char *buf, size_t len, loff_t *off)
{
	sprintf(buf, "%d\n", ip_drop);
	return strlen(buf);
}

static struct file_operations proc_fops = {
	.owner = THIS_MODULE,
	.read = proc_read,
	.write = proc_write
};

static int __init proc_init(void)
{
	proc_ip_drop = proc_create("ip_drop", 0644, NULL, &proc_fops);
	if (!proc_ip_drop) {
		printk(KERN_ALERT "Error: could not create ip_drop\n");
		return -ENOMEM;
	}

	nfho.hook = hook_func;
	nfho.hooknum = NF_INET_PRE_ROUTING;
	nfho.pf = PF_INET;
	nfho.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&nfho);

	return 0;
}

static void __exit proc_exit(void)
{
	remove_proc_entry("ip_drop", NULL);
	nf_unregister_hook(&nfho);
}

module_init(proc_init);
module_exit(proc_exit);
