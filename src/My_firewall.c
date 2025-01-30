#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/string.h>
#define BUFSIZE  255
#define TABLEMAXSIZE  255
#define IPADDRESS(addr) \
	((unsigned char *)&addr)[3], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[0]

static struct proc_dir_entry *ent;
// "172.217.194.99" - google used for testing

struct my_firewall_filter
{
	bool tcp_allow;
	bool icmp_allow;
	bool udp_allow;
	char **ip_table;
	//int *port_table;
	int rule_count;	
};

static struct my_firewall_filter filter = 
{
	.tcp_allow = true,
	.icmp_allow = false,
	.udp_allow = false,
	.ip_table = NULL,
	//.port_table = NULL,
	.rule_count = 0
}; 

static struct nf_hook_ops *nf_blockprotocol_ops = NULL; 
static struct nf_hook_ops *nf_blockip_ops = NULL; 

static ssize_t my_read(struct file *file, char __user *ubuf, size_t count, loff_t *ppos) // on read /proc/my_firewall_table
{
	char buf[BUFSIZE];
	int len=0;
	printk( KERN_DEBUG "My_firewall: Read Handler\n");
	if(*ppos > 0 || count < BUFSIZE)
		return 0;
	len += sprintf(buf,"TCP Allowed: %s\n", filter.tcp_allow ? "true" : "false");	// print protocol flags
	len += sprintf(buf + len,"ICMP Allowed: %s\n", filter.icmp_allow ? "true" : "false");
	len += sprintf(buf + len,"UDP Allowed: %s\n", filter.udp_allow ? "true" : "false");
	for (int i = 0; i < filter.rule_count; ++i)
		len += sprintf(buf + len,"%s\n", filter.ip_table[i]);	// print ip_table	
	if(copy_to_user(ubuf,buf,len))
		return -EFAULT;
	*ppos = len;
	return len;
}

static ssize_t my_write(struct file *file, const char __user *ubuf,size_t count, loff_t *ppos) // on write to /proc/my_firewall_table
{
	printk( KERN_DEBUG "My_firewall: Write Handler\n");
	int num, c, ip1, ip2, ip3, ip4;
	int rmpos = -1;
	char buf[BUFSIZE];
	char rmstr[BUFSIZE];
	char prot[BUFSIZE];
	bool flag;
	char command, tmp;	
	if(*ppos > 0 || count > BUFSIZE)
		return -EFAULT;
	if(copy_from_user(buf,ubuf,count))
		return -EFAULT;
	command = buf[0];
	printk( KERN_DEBUG "My_firewall: %c", command);	
	if (command =='a' || command == 'A') // add ip to table
	{
		num = sscanf(buf, "%c %d.%d.%d.%d", &tmp, &ip1, &ip2, &ip3, &ip4);
		if(num != 5)
			return -EFAULT;
		sprintf(filter.ip_table[filter.rule_count], "%d.%d.%d.%d", ip1, ip2, ip3, ip4);
		printk( KERN_DEBUG "My_firewall: Recieved command add ip %s", filter.ip_table[filter.rule_count]);
		filter.rule_count++;
				
	}
	else if (command =='r' || command == 'R') // rm ip from table
	{		
		num = sscanf(buf, "%c %d.%d.%d.%d", &tmp, &ip1, &ip2, &ip3, &ip4);
		if(num != 5)
			return -EFAULT;
		sprintf(rmstr, "%d.%d.%d.%d", ip1, ip2, ip3, ip4);
		printk( KERN_DEBUG "My_firewall: Recieved command remove ip %s", rmstr);
		for (int i = 0; i < filter.rule_count; ++i)
			if (!strcmp(filter.ip_table[i], rmstr))	// if matched
			{
				rmpos = i;
				printk( KERN_DEBUG "My_firewall: Located ip for removal. Pos: %d", rmpos);
				for (int j = rmpos; j < filter.rule_count; ++j)
					strcpy(filter.ip_table[j], filter.ip_table[j+1]);	// override every string after removed with its next one
				strcpy(filter.ip_table[filter.rule_count],"\0"); // clear the last string
				filter.rule_count--;
				break;
			}
		if (rmpos == -1)
			printk( KERN_DEBUG "My_firewall: No matching ip found");
	}
	else if (command =='c' || command == 'C') // clear table
	{
		for (int i = 0; i < filter.rule_count; ++i)
			strcpy(filter.ip_table[i],"\0");	
		filter.rule_count = 0;
	}
	else if (command =='f' || command == 'F') // flag change
	{
		num = sscanf(buf, "%c %s %d", &tmp, &prot, &flag);
		if (num != 3)
			return -EFAULT;
		if (!strcmp(prot, "tcp"))
		{
			printk( KERN_DEBUG "My_firewall: Set TCP flag to %s\n", flag ? "true" : "false");
			filter.tcp_allow = flag;
		}
		else if (!strcmp(prot, "icmp"))
		{
			printk( KERN_DEBUG "My_firewall: Set ICMP flag to %s\n", flag ? "true" : "false");
			filter.icmp_allow = flag;
		}
		else if (!strcmp(prot, "udp"))
		{
			printk( KERN_DEBUG "My_firewall: Set UDP flag to %s\n", flag ? "true" : "false");
			filter.udp_allow = flag;
		}
	}
	else
		printk( KERN_DEBUG "My_firewall: Recieved unknown command");		
	c = strlen(buf);
	*ppos = c;
	return c;
}

static struct proc_ops myops = 
{
	.proc_read = my_read,
	.proc_write = my_write
};

static unsigned int protocol_check(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) // this drops depending on protocol
{
	if (!skb)
		return NF_ACCEPT;
	struct sk_buff *sb = skb;
	struct iphdr *iph = ip_hdr(sb);
	struct udphdr *udph = NULL;
	if(iph->protocol == IPPROTO_UDP) // UDP check
	{
		if (filter.udp_allow)
		{
			udph = udp_hdr(sb);
			if(ntohs(udph->dest) == 53) 
				return NF_ACCEPT;
		}
		else
		{
			printk( KERN_DEBUG "My_firewall: Droping UDP packet - UDP is blocked");
			return NF_DROP;
		}
		
	}
	else if (iph->protocol == IPPROTO_TCP) // TCP check
	{
		if (filter.tcp_allow)
			return NF_ACCEPT;
		else
		{
			printk( KERN_DEBUG "My_firewall: Droping TCP packet - TCP is blocked");
			return NF_DROP;
		}
	}
	else if (iph->protocol == IPPROTO_ICMP) // ICMP check
	{
		if (filter.icmp_allow)
			return NF_ACCEPT;
		else
		{
			printk( KERN_DEBUG "My_firewall: Droping ICMP packet - ICMP is blocked");
			return NF_DROP;
		}
	}
	return NF_ACCEPT;
}	
	
static unsigned int ip_check(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) // this drops from specific ip
{	
	if (!skb)
		return NF_ACCEPT;
	struct sk_buff *sb = skb;
	struct iphdr *iph = ip_hdr(sb);
	u32 sip = ntohl(iph->saddr);
	char *str = (char *)kmalloc(16, GFP_KERNEL);	
	sprintf(str, "%u.%u.%u.%u", IPADDRESS(sip)); // convert sip recieved from skb to str
	for (int i = 0; i < filter.rule_count; ++i)
		if(!strcmp(str, filter.ip_table[i])) // if it matches drop the package
		{	
			printk(KERN_DEBUG "My_firewall: Drop packet from ip %s\n", str);
			return NF_DROP;
		} 
	return NF_ACCEPT;	// if not let through
}	

static int __init my_firewal_init(void) 
{
	printk(KERN_INFO "My_firewall: init");
	filter.ip_table = (char**) kmalloc(TABLEMAXSIZE * sizeof(char*), GFP_KERNEL);	// allocate table
	for (int i = 0; i < TABLEMAXSIZE; ++i)
		filter.ip_table[i] = (char *) kmalloc(16, GFP_KERNEL);
	ent=proc_create("my_firewall_table",0660,NULL,&myops);	// create /proc/my_firewall_table	
	nf_blockprotocol_ops= (struct nf_hook_ops*)kcalloc(1,  sizeof(struct nf_hook_ops), GFP_KERNEL); // alocate the hook struct
	if (nf_blockprotocol_ops != NULL) 
	{
		nf_blockprotocol_ops->hook = (nf_hookfn*)protocol_check;	// assign function
		nf_blockprotocol_ops->hooknum = NF_INET_PRE_ROUTING;	// pre-routing
		nf_blockprotocol_ops->pf = NFPROTO_IPV4;			// ipv4
		nf_blockprotocol_ops->priority = NF_IP_PRI_FIRST;	// first priority		
		nf_register_net_hook(&init_net, nf_blockprotocol_ops);
	}
	nf_blockip_ops = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	if (nf_blockip_ops != NULL) 
	{
		nf_blockip_ops->hook = (nf_hookfn*)ip_check;
		nf_blockip_ops->hooknum = NF_INET_PRE_ROUTING;
		nf_blockip_ops->pf = NFPROTO_IPV4;
		nf_blockip_ops->priority = NF_IP_PRI_FIRST + 1;	// second priority
		nf_register_net_hook(&init_net, nf_blockip_ops);
	}
	return 0;
}

static void __exit my_firewal_exit(void) 
{
	if(nf_blockprotocol_ops!= NULL)		// free hooks
	{
		nf_unregister_net_hook(&init_net, nf_blockprotocol_ops);
		kfree(nf_blockprotocol_ops);
	}
	if (nf_blockip_ops  != NULL) 
	{
		nf_unregister_net_hook(&init_net, nf_blockip_ops);
		kfree(nf_blockip_ops);
	}	
	for (int i = 0; i < TABLEMAXSIZE; ++i)	// free ip table
		kfree(filter.ip_table[i]);
	kfree(filter.ip_table);
	proc_remove(ent);	// remove /proc/my_firewall_table
	printk(KERN_INFO "My_firewall: Exit");
}

module_init(my_firewal_init);
module_exit(my_firewal_exit);

MODULE_LICENSE("GPL");
