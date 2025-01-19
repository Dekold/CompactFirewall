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
static char **ip_table;
static int rule_count = 0;
static struct nf_hook_ops *nf_blockicmppkt_ops = NULL; // Block icmp (ping, traceroute...)
static struct nf_hook_ops *nf_blockipaddr_ops = NULL; // Block ip-adress

static ssize_t my_read(struct file *file, char __user *ubuf,size_t count, loff_t *ppos) // on read /proc/my_firewall_table
{
	char buf[BUFSIZE];
	int len=0;
	printk( KERN_DEBUG "My_firewall: Read Handler\n");
	if(*ppos > 0 || count < BUFSIZE)
		return 0;
	for (int i = 0; i < rule_count; ++i)
		len += sprintf(buf + len,"%s\n", ip_table[i]);	// print ip_table	
	if(copy_to_user(ubuf,buf,len))
		return -EFAULT;
	*ppos = len;
	return len;
}

static ssize_t my_write(struct file *file, const char __user *ubuf,size_t count, loff_t *ppos) // on write to /proc/my_firewall_table
{
	printk( KERN_DEBUG "My_firewall: Write Handler\n");
	int num,c, ip1, ip2, ip3, ip4;
	int rmpos = -1;
	char buf[BUFSIZE];
	char rmstr[BUFSIZE];
	char command;
	if(*ppos > 0 || count > BUFSIZE)
		return -EFAULT;
	if(copy_from_user(buf,ubuf,count))
		return -EFAULT;
	num = sscanf(buf, "%c %d.%d.%d.%d", &command, &ip1, &ip2, &ip3, &ip4);
	if(num != 5)
		return -EFAULT;
	if (command =='a' || command == 'A') // add ip to table
	{
		sprintf(ip_table[rule_count], "%d.%d.%d.%d", ip1, ip2, ip3, ip4);
		printk( KERN_DEBUG "My_firewall: Recieved command add ip %s", ip_table[rule_count]);
		rule_count++;
				
	}
	else if (command =='r' || command == 'R') // rm ip from table
	{		
		sprintf(rmstr, "%d.%d.%d.%d", ip1, ip2, ip3, ip4);
		printk( KERN_DEBUG "My_firewall: Recieved command remove ip %s", rmstr);
		for (int i = 0; i < rule_count; ++i)
		{
			if (!strcmp(ip_table[i], rmstr))	// if matched
			{
				rmpos = i;
				printk( KERN_DEBUG "My_firewall: Located ip for removal. Pos: %d", rmpos);
				for (int j = rmpos; j < rule_count; ++j)
				{
					strcpy(ip_table[j], ip_table[j+1]);	// override every string after removed with its next one
				}
				strcpy(ip_table[rule_count],"\0"); // clear the last string
				rule_count --;
				break;
			}
		}
		if (rmpos == -1)
		{
			printk( KERN_DEBUG "My_firewall: No matching ip found");	
		}	
	}
	else if (command =='c' || command == 'C') // clear table
	{
		for (int i = 0; i < rule_count; ++i)
		{
			strcpy(ip_table[i],"\0");	
		}
		rule_count = 0;
	}
	else
	{
		printk( KERN_DEBUG "My_firewall: Recieved unknown command");		
	}
	c = strlen(buf);
	*ppos = c;
	return c;
}

static struct proc_ops myops = 
{
	.proc_read = my_read,
	.proc_write = my_write
};

static unsigned int block_ip(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) // this drops from specific ip
{
	if (!skb)
		return NF_ACCEPT;
	char *str = (char *)kmalloc(16, GFP_KERNEL);	// str buffer
	u32 sip;
	struct sk_buff *sb = NULL;
	struct iphdr *iph;
	sb = skb;
	iph = ip_hdr(sb);
	sip = ntohl(iph->saddr);
	sprintf(str, "%u.%u.%u.%u", IPADDRESS(sip)); // convert sip recieved from skb to str
	for (int i = 0; i < rule_count; ++i)
	{
		if(!strcmp(str, ip_table[i])) // if it matches drop the package
		{	
			printk(KERN_DEBUG "My_firewall: Drop packet from ip %s\n", str);
			return NF_DROP;
		} 
	}
	return NF_ACCEPT;	// if not let through
}

static unsigned int block_icmp(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) // this drops icmp
{
	struct iphdr *iph;
	struct udphdr *udph;
	if(!skb)
		return NF_ACCEPT;
	iph = ip_hdr(skb);
	if(iph->protocol == IPPROTO_UDP) // UDP is allowed
	{
		udph = udp_hdr(skb);
		if(ntohs(udph->dest) == 53) 
		{
			return NF_ACCEPT;
		}
	}
	else if (iph->protocol == IPPROTO_TCP) // TCP is allowed
	{
		return NF_ACCEPT;
	}
	else if (iph->protocol == IPPROTO_ICMP) // ICMP is not allowed
	{
		printk(KERN_DEBUG "My_firewall: Drop ICMP packet \n");
		return NF_DROP;
	}
	return NF_ACCEPT;
}

static int __init my_firewal_init(void) 
{
	printk(KERN_INFO "My_firewall: init");
	ip_table = (char**) kmalloc(TABLEMAXSIZE * sizeof(char*), GFP_KERNEL);	// allocate table
	for (int i = 0; i < TABLEMAXSIZE; ++i)
		ip_table[i] = (char *) kmalloc(16, GFP_KERNEL);
	ent=proc_create("my_firewall_table",0660,NULL,&myops);	// create /proc/mydev	
	nf_blockicmppkt_ops = (struct nf_hook_ops*)kcalloc(1,  sizeof(struct nf_hook_ops), GFP_KERNEL); // alocate the hook struct
	if (nf_blockicmppkt_ops != NULL) 
	{
		nf_blockicmppkt_ops->hook = (nf_hookfn*)block_icmp;	// assign fucntion
		nf_blockicmppkt_ops->hooknum = NF_INET_PRE_ROUTING;	// pre-routing
		nf_blockicmppkt_ops->pf = NFPROTO_IPV4;			// ipv4
		nf_blockicmppkt_ops->priority = NF_IP_PRI_FIRST;	// first priority		
		nf_register_net_hook(&init_net, nf_blockicmppkt_ops);
	}
	nf_blockipaddr_ops = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	if (nf_blockipaddr_ops != NULL) 
	{
		nf_blockipaddr_ops->hook = (nf_hookfn*)block_ip;
		nf_blockipaddr_ops->hooknum = NF_INET_PRE_ROUTING;
		nf_blockipaddr_ops->pf = NFPROTO_IPV4;
		nf_blockipaddr_ops->priority = NF_IP_PRI_FIRST + 1;	// second priority
		nf_register_net_hook(&init_net, nf_blockipaddr_ops);
	}
	return 0;
}

static void __exit my_firewal_exit(void) 
{
	if(nf_blockicmppkt_ops != NULL)		// free hooks
	{
		nf_unregister_net_hook(&init_net, nf_blockicmppkt_ops);
		kfree(nf_blockicmppkt_ops);
	}
	if (nf_blockipaddr_ops  != NULL) 
	{
		nf_unregister_net_hook(&init_net, nf_blockipaddr_ops);
		kfree(nf_blockipaddr_ops);
	}	
	for (int i = 0; i < TABLEMAXSIZE; ++i)	// free ip table
		kfree(ip_table[i]);
	kfree(ip_table);
	proc_remove(ent);	// remove /proc/my_firewall_table
	printk(KERN_INFO "My_firewall: Exit");
}

module_init(my_firewal_init);
module_exit(my_firewal_exit);

MODULE_LICENSE("GPL");
