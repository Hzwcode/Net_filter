/*************************************************************************
    > File Name: hook.c
    > Author: hzw
    > Mail: 1359434736@qq.com 
    > Created Time: 2016年02月22日 星期一 11时59分57秒
 ************************************************************************/
#include "netfilter.h"

MODULE_LICENSE("GPL");

RULE *rule_head;

__be16 GetProtocol(struct sk_buff *skb){
	struct sk_buff *sk;
	struct iphdr *ip;
	sk = skb_copy(skb, 1);
	ip = ip_hdr(sk);
	return ip->protocol;
}

uint32_t GetAddr(struct sk_buff *skb, int flag){
	struct sk_buff *sk;
	struct iphdr *ip;
	sk = skb_copy(skb, 1);
	ip = ip_hdr(sk);
	if(flag == SRC)
		return ip->saddr;
	else if(flag == DEST)
		return ip->daddr;
	else
		return 0;
}

uint16_t GetPort(struct sk_buff *skb, int flag){
	struct sk_buff *sk;
	struct tcphdr *tcph;
	struct udphdr *udph;
	uint16_t port = 0;
	sk = skb_copy(skb, 1);
	tcph = tcp_hdr(sk);
	udph = udp_hdr(sk);

	switch(GetProtocol(skb)){
		case IPPROTO_TCP:
			if(flag == SRC)
				port = ntohs(tcph->source);
			else if(flag == DEST)
				port = ntohs(tcph->dest);
			break;
		case IPPROTO_UDP:
			if(flag == SRC)
				port = ntohs(udph->source);
			else if(flag == DEST)
				port = ntohs(udph->dest);
			break;
		default:
			port = ANY_PORT;
	}
	return port;
}

unsigned int hook_pre_routing(unsigned int hooknum,
			struct sk_buff *skb,
			const struct net_device *in,
			const struct net_device *out,
			int (*okfn)(struct sk_buff *))
{
	__be16 protocol;
	printk("hook_pre_routing\n");
	protocol = GetProtocol(skb);
	
	printk("time = %lld\n",skb->tstamp.tv64);

	if(protocol == IPPROTO_TCP){
		printk("There is a 【tcp】 package.\n");
	}
	else if(protocol == IPPROTO_UDP){
		printk("There is a 【udp】 package.\n");
	}
	else if(protocol == IPPROTO_ICMP){
		printk("There is a 【icmp】 package.\n");
	}
	
	return NF_ACCEPT;
}

unsigned int hook_local_in(unsigned int hooknum,
			struct sk_buff *skb,
			const struct net_device *in,
			const struct net_device *out,
			int (*okfn)(struct sk_buff *))
{
	
	printk("hook_local_in\n");
	return NF_ACCEPT;
}

unsigned int hook_forward(unsigned int hooknum,
			struct sk_buff *skb,
			const struct net_device *in,
			const struct net_device *out,
			int (*okfn)(struct sk_buff *))
{
	//return NF_DROP;
	printk("hook_forward\n");
	return NF_ACCEPT;
}

unsigned int hook_local_out(unsigned int hooknum,
			struct sk_buff *skb,
			const struct net_device *in,
			const struct net_device *out,
			int (*okfn)(struct sk_buff *))
{
	//return NF_DROP;
	printk("hook_local_out\n");
	return NF_ACCEPT;
}

unsigned int hook_post_routing(unsigned int hooknum,
			struct sk_buff *skb,
			const struct net_device *in,
			const struct net_device *out,
			int (*okfn)(struct sk_buff *))
{
	//return NF_DROP;
	printk("hook_post_routing\n");
	return NF_ACCEPT;
}
