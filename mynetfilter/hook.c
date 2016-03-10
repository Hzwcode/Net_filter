/*************************************************************************
    > File Name: hook.c
    > Author: hzw
    > Mail: 1359434736@qq.com 
    > Created Time: 2016年02月22日 星期一 11时59分57秒
 ************************************************************************/
#include "netfilter.h"
#include "chardev.h"

MODULE_LICENSE("GPL");

extern struct rule rule_pre_routing;
extern struct rule rule_local_out;
extern struct mem_dev *mem_log;
extern int log_len;

int n_match = 0;

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
		return ANY_ADDR;
}

uint16_t GetPort(struct sk_buff *skb, int flag){
	struct sk_buff *sk;
	struct tcphdr *tcph;
	struct udphdr *udph;
	uint16_t port = ANY_PORT;
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
	Bool flag = false;
	addr1_temp = ntohl(addr1);
	addr2_temp = ntohl(addr2);

	addr1_temp = MASK_IP(addr1_temp, mask);
	addr2_temp = MASK_IP(addr2_temp, mask);

	flag = (addr1_temp == addr2_temp);

	if(flag == true){
		printk("[Addr match!!!]\n");
	}

	return flag;
}

Bool CompareTime(struct rule_time rule_tm, struct rtc_time tm){
	int hour, min, sec;
	int lhour, lmin, lsec, rhour, rmin, rsec;
	int nowsec, ltimesec, rtimesec;
  	hour = tm.tm_hour;
  	min = tm.tm_min;
    sec = tm.tm_sec;
    lhour = rule_tm.ltime.tm_hour;
  	lmin = rule_tm.ltime.tm_min;
    lsec = rule_tm.ltime.tm_sec;
    rhour = rule_tm.rtime.tm_hour;
  	rmin = rule_tm.rtime.tm_min;
    rsec = rule_tm.rtime.tm_sec;

    nowsec = hour * 3600 + min * 60 + sec;
	ltimesec = lhour * 3600 + lmin * 60 + lsec;
	rtimesec = rhour * 3600 + rmin * 60 + rsec;

	if(nowsec >= ltimesec && nowsec <= rtimesec){
		printk("[Time match!!!]\n");
    	printk("the package time: %02d:%02d:%02d\n", hour, min, sec);
    	printk("rule  begin time: %02d:%02d:%02d\n", lhour, lmin, lsec);
    	printk("rule  end   time: %02d:%02d:%02d\n", rhour, rmin, rsec);
		return true;
	}
    return false;
}
/*
Bool filter_pre_routing(struct sk_buff *skb){
	struct rule *ptr;
	uint32_t s_addr, d_addr;
	__u8 protocol;
	uint16_t s_port, d_port;
	struct rtc_time tm;
	struct timeval timeval;
	unsigned long local_time;
	Bool match = false;
	Bool flag = false;
	int n = 0;

	if(!skb) 
		return false;
	
	protocol = GetProtocol(skb);
	s_addr = GetAddr(skb, SRC);
	d_addr = GetAddr(skb, DEST);
	s_port = GetPort(skb, SRC);
	d_port = GetPort(skb, DEST);

	do_gettimeofday(&timeval);
	local_time = (u32)(timeval.tv_sec + (8 * 60 * 60));
	rtc_time_to_tm(local_time, &tm);
	
	list_for_each_entry(ptr, &rule_pre_routing.list, list){
		n++;
		match = ptr->action ? 0 : 1;
		if(!match){
			//printk("action false, default accept.\n");
			continue;
		}
		match = (ANY_TIME(ptr->tm) || CompareTime(ptr->tm, tm));
		if(!match){
			//printk("time false, does not match.\n");
			continue;
		}
		match = (ptr->saddr.addr == ANY_ADDR ? true : CompareID_with_mask(ptr->saddr.addr,s_addr,ptr->saddr.mask));
		if(!match){
			//printk("src_addr false, does not match.\n");
			continue;
		}
		match = (ptr->daddr.addr == ANY_ADDR ? true : CompareID_with_mask(ptr->daddr.addr,d_addr,ptr->daddr.mask));
		if(!match){
			//printk("dest_addr false, does not match.\n");
			continue;
		}	
		match = (ptr->protocol == ANY_PROTOCOL) ? true : (ptr->protocol == protocol);
		if(!match){
			//printk("protocol false, does not match.\n");
			continue;
		}
		match = (ptr->sport == ANY_PORT) ? true : (ptr->sport == s_port);
		if(!match){
			//printk("src_port false, does not match.\n");
			continue;
		}
		match = (ptr->dport == ANY_PORT) ? true : (ptr->dport == d_port);
		if(!match){
			//printk("dest_port false, does not match.\n");
			continue;
		}
		if(match){
			flag = true;
			printk("Pre_routing: receive a packet from %pI4 and drop!\n", &s_addr);
			printk("match the regulation %d success!\n", n);
			printk("-----------------------------\n");
			printk("[Drop a packet]\n");
			printk(" saddr:      %pI4\n", &s_addr);
			printk(" sport:      %u\n\n", s_port);
			printk(" daddr:      %pI4\n", &d_addr);
			printk(" dport:      %u\n\n", d_port);
			printk(" protocol:   %hhu\n", protocol);
			printk("-----------------------------\n");

			break;
		}
	}
	return flag;
}
*/

Bool filter_local_out(struct sk_buff *skb){
	struct rule *ptr;
	uint32_t s_addr, d_addr;
	__u8 protocol;
	uint16_t s_port, d_port;
	struct rtc_time tm;
	struct timeval timeval;
	unsigned long local_time;
	Bool match = false;
	Bool flag = false;
	int n = 0;
	int ret;

	if(!skb) 
		return false;
	
	protocol = GetProtocol(skb);
	s_addr = GetAddr(skb, SRC);
	d_addr = GetAddr(skb, DEST);
	s_port = GetPort(skb, SRC);
	d_port = GetPort(skb, DEST);
	
	list_for_each_entry(ptr, &rule_local_out.list, list){
		n++;
		do_gettimeofday(&timeval);
		local_time = (u32)(timeval.tv_sec + (8 * 60 * 60));
		rtc_time_to_tm(local_time, &tm);

		match = false;
		match = (ANY_TIME(ptr->tm) || CompareTime(ptr->tm, tm));
		if(!match){
			//printk("time false, does not match.\n");
			continue;
		}
		match = (ptr->saddr.addr == ANY_ADDR ? true : CompareID_with_mask(ptr->saddr.addr,s_addr,ptr->saddr.mask));
		if(!match){
			//printk("src_addr false, does not match.\n");
			continue;
		}
		match = (ptr->daddr.addr == ANY_ADDR ? true : CompareID_with_mask(ptr->daddr.addr,d_addr,ptr->daddr.mask));
		if(!match){
			//printk("dest_addr false, does not match.\n");
			continue;
		}	
		match = (ptr->protocol == ANY_PROTOCOL) ? true : (ptr->protocol == protocol);
		if(!match){
			//printk("protocol false, does not match.\n");
			continue;
		}
		match = (ptr->sport == ANY_PORT) ? true : (ptr->sport == s_port);
		if(!match){
			//printk("src_port false, does not match.\n");
			continue;
		}
		match = (ptr->dport == ANY_PORT) ? true : (ptr->dport == d_port);
		if(!match){
			//printk("dest_port false, does not match.\n");
			continue;
		}
		match = ptr->action ? 0 : 1;
		
		if(match){
			flag = true;
			++n_match;
			if(mem_log->size - log_len > 120){
				ret = sprintf(mem_log->data + log_len, 
				    "time@[%04d-%02d-%02d %02d:%02d:%02d] %hhu.%hhu.%hhu.%hhu/%u:%u to %hhu.%hhu.%hhu.%hhu/%u:%u, protocol: %u, ltime: %02d:%02d:%02d, rtime: %02d:%02d:%02d, action: %s\n", 
					tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, 
					((unsigned char *)&ptr->saddr.addr)[0], 
					((unsigned char *)&ptr->saddr.addr)[1], 
					((unsigned char *)&ptr->saddr.addr)[2], 
					((unsigned char *)&ptr->saddr.addr)[3], 
					ptr->saddr.mask, ptr->sport, 
					((unsigned char *)&ptr->daddr.addr)[0], 
					((unsigned char *)&ptr->daddr.addr)[1], 
					((unsigned char *)&ptr->daddr.addr)[2], 
					((unsigned char *)&ptr->daddr.addr)[3], 
					ptr->daddr.mask, ptr->dport, 
					ptr->protocol, 
					ptr->tm.ltime.tm_hour, ptr->tm.ltime.tm_min, ptr->tm.ltime.tm_sec, 
					ptr->tm.rtime.tm_hour, ptr->tm.rtime.tm_min, ptr->tm.rtime.tm_sec, 
					ptr->action ? "Permit" : "Reject");
				log_len += ret;
			} 
			else{
				printk("Log buffer full!\n");
			}

			printk("-----------------------------\n");
			printk("<time %d> Local_out: send a packet to %pI4 and drop!\n", n_match, &d_addr);
			printk("match the regulation %d success!\n", n);
			printk(" saddr:      %pI4\n", &s_addr);
			printk(" sport:      %u\n\n", s_port);
			printk(" daddr:      %pI4\n", &d_addr);
			printk(" dport:      %u\n\n", d_port);
			printk(" protocol:   %hhu\n", protocol);
			printk("-----------------------------\n");
			break;
		}
		else{
			flag = false;
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
	if(filter_pre_routing(skb) == true) {
		return NF_DROP;
	}
	*/
	return NF_ACCEPT;
}

unsigned int hook_local_out(unsigned int hooknum,
			struct sk_buff *skb,
			const struct net_device *in,
			const struct net_device *out,
			int (*okfn)(struct sk_buff *))
{
	//printk("hook_local_out\n");
	if(filter_local_out(skb) == true) {
		return NF_DROP;
	}
	return NF_ACCEPT;
}
/*
unsigned int hook_local_in(unsigned int hooknum,
			struct sk_buff *skb,
			const struct net_device *in,
			const struct net_device *out,
			int (*okfn)(struct sk_buff *))
{
	//printk("hook_local_in\n");
	if(filter_local_in(skb) == true) {
		return NF_DROP;
	}
	return NF_ACCEPT;
}

unsigned int hook_forward(unsigned int hooknum,
			struct sk_buff *skb,
			const struct net_device *in,
			const struct net_device *out,
			int (*okfn)(struct sk_buff *))
{
	printk("hook_forward\n");
	return NF_ACCEPT;
}



unsigned int hook_post_routing(unsigned int hooknum,
			struct sk_buff *skb,
			const struct net_device *in,
			const struct net_device *out,
			int (*okfn)(struct sk_buff *))
{
	printk("hook_post_routing\n");
	return NF_ACCEPT;
}
*/