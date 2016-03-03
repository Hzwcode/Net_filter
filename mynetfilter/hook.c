/*************************************************************************
    > File Name: hook.c
    > Author: hzw
    > Mail: 1359434736@qq.com 
    > Created Time: 2016年02月22日 星期一 11时59分57秒
 ************************************************************************/
#include "netfilter.h"
#include "chardev.h"

MODULE_LICENSE("GPL");

extern struct rule rule_head;
extern struct mem_dev *mem_devp;

__u8 GetProtocol(struct sk_buff *skb){
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

	switch(GetProtocol(sk)){
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


Bool CompareID_with_mask(uint32_t addr1, uint32_t addr2, uint8_t mask){
	uint32_t addr1_temp, addr2_temp;
	addr1_temp = MASK_IP(addr1, mask);
	addr2_temp = MASK_IP(addr2, mask);
	return (addr1_temp == addr2_temp);
}

Bool CompareTime(struct rule_time rule_tm, ktime_t package_time){
	struct rtc_time tm;
	int hour, min, sec;
	//int year, month, mday, wday, yday;
	rtc_time_to_tm(package_time.tv64/1000000000 + (8 * 60 * 60), &tm);
	//year = tm.tm_year + 1900;
  	//month = tm.tm_mon + 1;
  	//mday = tm.tm_mday;
  	hour = tm.tm_hour;
  	min = tm.tm_min;
    sec = tm.tm_sec;
    //wday = tm.tm_wday;
    //yday = tm.tm_yday;
	//printk("time@ (%04d-%02d-%02d %02d:%02d:%02d)\n",year, month, mday, hour, min, sec);
    if(rule_tm.valid == true
    	&& hour >= rule_tm.ltime.tm_hour && hour <= rule_tm.rtime.tm_hour
    	&& min  >= rule_tm.ltime.tm_min  && min  <= rule_tm.rtime.tm_min
    	&& sec  >= rule_tm.ltime.tm_sec  && sec  <= rule_tm.rtime.tm_sec)
    {
    	return true;
    }
    return false;
}

Bool filter(struct sk_buff *skb){
	struct sk_buff *sk; 
	struct rule *ptr;
	uint32_t s_addr, d_addr;
	__u8 protocol;
	uint16_t s_port, d_port;
	ktime_t tm;
	Bool match = false;
	Bool flag = false;

	if(!skb) 
		return false;
	
	sk = skb_copy(skb,1);
	protocol = GetProtocol(sk);
	s_addr = GetAddr(sk, SRC);
	d_addr = GetAddr(sk, DEST);
	s_port = GetPort(sk, SRC);
	d_port = GetPort(sk, DEST);
	tm = sk->tstamp;

	list_for_each_entry(ptr, &rule_head.list, list){
		match = ptr->action ? 0 : 1;
		if(!match){
			printk("action false, default accept.\n");
			continue;
		}
		match = (ANY_TIME(ptr->tm) || CompareTime(ptr->tm, tm));
		if(!match){
			printk("time false, does not match.\n");
			continue;
		}
		match = (ptr->saddr.addr == ANY_ADDR ? true : CompareID_with_mask(ptr->saddr.addr,s_addr,ptr->saddr.mask));
		if(!match){
			printk("src_addr false, does not match.\n");
			continue;
		}
		match = (ptr->daddr.addr == ANY_ADDR ? true : CompareID_with_mask(ptr->daddr.addr,d_addr,ptr->daddr.mask));
		if(!match){
			printk("dest_addr false, does not match.\n");
			continue;
		}	
		match = (ptr->sport == ANY_PORT ? true : ptr->sport == s_port);
		if(!match){
			printk("src_port false, does not match.\n");
			continue;
		}
		match = (ptr->dport == ANY_PORT ? true : ptr->dport == d_port);
		if(!match){
			printk("dest_port false, does not match.\n");
			continue;
		}
		match = (ptr->protocol == ANY_PROTOCOL ? true : ptr->protocol == protocol);
		if(!match){
			printk("protocol false, does not match.\n");
			continue;
		}
		if(match){
			flag = true;
			break;
		}
	}
	return flag;
}

unsigned int hook_pre_routing(unsigned int hooknum,
			struct sk_buff *skb,
			const struct net_device *in,
			const struct net_device *out,
			int (*okfn)(struct sk_buff *))
{
	//printk("hook_pre_routing\n");
	/*
	if(filter(skb) == true) {
		printk("receive a packet from %s and drop", addr2inet(GetAddr(skb, SRC)));
		return NF_DROP;
	}
	*/
	return NF_ACCEPT;
}

unsigned int hook_local_in(unsigned int hooknum,
			struct sk_buff *skb,
			const struct net_device *in,
			const struct net_device *out,
			int (*okfn)(struct sk_buff *))
{
	
	//printk("hook_local_in\n");
	return NF_ACCEPT;
}

unsigned int hook_forward(unsigned int hooknum,
			struct sk_buff *skb,
			const struct net_device *in,
			const struct net_device *out,
			int (*okfn)(struct sk_buff *))
{
	//printk("hook_forward\n");
	return NF_ACCEPT;
}

unsigned int hook_local_out(unsigned int hooknum,
			struct sk_buff *skb,
			const struct net_device *in,
			const struct net_device *out,
			int (*okfn)(struct sk_buff *))
{
	//printk("hook_local_out\n");
	/*
	if(filter(skb) == true) {
		printk("send a packet to %s and drop", addr2inet(GetAddr(skb, DEST)));
		return NF_DROP;
	}
	*/
	return NF_ACCEPT;
}

unsigned int hook_post_routing(unsigned int hooknum,
			struct sk_buff *skb,
			const struct net_device *in,
			const struct net_device *out,
			int (*okfn)(struct sk_buff *))
{
	//printk("hook_post_routing\n");
	return NF_ACCEPT;
}
