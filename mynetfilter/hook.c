/*************************************************************************
    > File Name: hook.c
    > Author: hzw
    > Mail: 1359434736@qq.com 
    > Created Time: 2016年02月22日 星期一 11时59分57秒
 ************************************************************************/
#include "netfilter.h"
#include "chardev.h"

MODULE_LICENSE("GPL");

RULE *rule_head;
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

Bool CompareTime(RULE_TIME rule_time, ktime_t package_time){
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
    if(rule_time.valid == true
    	&& hour >= rule_time.begin_time.tm_hour && hour <= rule_time.end_time.tm_hour
    	&& min  >= rule_time.begin_time.tm_min  && min  <= rule_time.end_time.tm_min
    	&& sec  >= rule_time.begin_time.tm_sec  && sec  <= rule_time.end_time.tm_sec)
    {
    	return true;
    }
    return false;
}

Bool filter(struct sk_buff *skb){
	struct sk_buff *sk; 
	RULE *ptr;
	uint32_t s_addr, d_addr;
	__u8 protocol;
	uint16_t s_port, d_port;
	ktime_t tm;
	Bool success;

	if(!skb) 
		return false;
	
	sk = skb_copy(skb,1);
	protocol = GetProtocol(sk);
	s_addr = GetAddr(sk, SRC);
	d_addr = GetAddr(sk, DEST);
	s_port = GetPort(sk, SRC);
	d_port = GetPort(sk, DEST);
	tm = sk->tstamp;

	ptr = rule_head;
	while(ptr){
		success  = ptr->action;
		success &= ptr->s_addr.addr == ANY_ADDR ? true : CompareID_with_mask(ptr->s_addr.addr,s_addr,ptr->s_addr.mask);
		success &= ptr->d_addr.addr == ANY_ADDR ? true : CompareID_with_mask(ptr->d_addr.addr,d_addr,ptr->d_addr.mask);
		success &= ptr->s_port == ANY_PORT ? true : ptr->s_port == s_port;
		success &= ptr->d_port == ANY_PORT ? true : ptr->d_port == d_port;
		success &= ptr->protocol == ANY_PROTOCOL ? true : ptr->protocol == protocol;
		success &= CompareTime(ptr->tm, tm);
		if(success) 
			break;
		ptr = ptr->next;
	}
	if(!ptr) 
		success = false;
	return success;
}


unsigned int hook_pre_routing(unsigned int hooknum,
			struct sk_buff *skb,
			const struct net_device *in,
			const struct net_device *out,
			int (*okfn)(struct sk_buff *))
{
	//printk("hook_pre_routing\n");
	/*
	if(filter(skb) == true)
		return NF_DROP;
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
	if(filter(skb) == true)
		return NF_DROP;
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
