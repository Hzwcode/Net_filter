/*************************************************************************
    > File Name: test_mod2.c
    > Author: ma6174
    > Mail: ma6174@163.com 
    > Created Time: 2016年02月22日 星期一 11时59分57秒
 ************************************************************************/


#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/string.h>
#include <linux/kmod.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/icmp.h>
#include <net/sock.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>

MODULE_LICENSE("GPL");

static char *parg = "119.75.217.109";
module_param(parg, charp, S_IRUGO);

/*
static char *parg[2] = {"119.75.217.109", "119.75.218.70"};
static int nr_fish = 2;

module_param_array(parg, charp, &nr_fish, S_IRUGO);
*/

unsigned int inet_addr(char *str){
	int a, b, c, d;
	char arr[4];
	sscanf(str, "%d.%d.%d.%d", &a, &b, &c, &d);
	arr[0] = a;
	arr[1] = b;
	arr[2] = c;
	arr[3] = d;
	return *(unsigned int*)arr;
}

unsigned int hook_func(unsigned int hooknum,
			struct sk_buff *skb,
			const struct net_device *in,
			const struct net_device *out,
			int (*okfn)(struct sk_buff *))
{
	struct sk_buff *sk = skb_copy(skb, 1);
	struct iphdr *ip;

	if(!sk){
		return NF_ACCEPT;
	}
	ip = ip_hdr(sk);
	if(ip->saddr == inet_addr(parg)){
		return NF_DROP;
	}
	else{
		return NF_ACCEPT;
	}
}
