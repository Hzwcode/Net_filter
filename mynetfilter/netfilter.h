#ifndef __NETFILTER__
#define __NETFILTER__

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
#include <linux/udp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/icmp.h>
#include <linux/rtc.h>
#include <linux/time.h>
#include <net/sock.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>

typedef short Bool;
#define true 1
#define false 0

#define SRC 0
#define DEST 1

#define PERMIT 1
#define REJECT 0

#define ANY_ADDR 0
#define ANY_PORT 0xffff
#define ANY_PROTOCOL 0xff
#define ANY_TIME(tm) (tm.valid == 0)

#define MASK_IP(x, mask) (x & (0xffffffff << (!mask ? 0 : (32 - mask))))

struct rule_time{
     struct rtc_time ltime;
     struct rtc_time rtime;
     Bool valid;
}; 

//规则结构
typedef struct rule{
     struct{
          uint32_t addr;        //IP地址
          uint8_t mask;         //掩码
     }saddr, daddr;             //源IP地址，目的IP地址
	uint16_t sport, dport;     //源端口，目的端口
	__u8 protocol;             //协议类型                  
     struct rule_time tm;       //时间段
	Bool action;               //动作

     struct list_head list;     //双向链表
}RULE;

unsigned int hook_pre_routing(unsigned int hooknum,
                         struct sk_buff *skb,
                         const struct net_device *in,
                         const struct net_device *out,
                         int (*okfn)(struct sk_buff *));
/*
unsigned int hook_local_in(unsigned int hooknum,
                         struct sk_buff *skb,
                         const struct net_device *in,
                         const struct net_device *out,
                         int (*okfn)(struct sk_buff *));

unsigned int hook_forward(unsigned int hooknum,
                         struct sk_buff *skb,
                         const struct net_device *in,
                         const struct net_device *out,
                         int (*okfn)(struct sk_buff *));
*/
unsigned int hook_local_out(unsigned int hooknum,
                         struct sk_buff *skb,
                         const struct net_device *in,
                         const struct net_device *out,
                         int (*okfn)(struct sk_buff *));
/*
unsigned int hook_post_routing(unsigned int hooknum,
                         struct sk_buff *skb,
                         const struct net_device *in,
                         const struct net_device *out,
                         int (*okfn)(struct sk_buff *));
*/
static inline unsigned int inet_addr(char *str)
{
     int a, b, c, d;
     char arr[4];
     sscanf(str, "%d.%d.%d.%d", &a, &b, &c, &d);
     arr[0] = a; arr[1] = b; arr[2] = c; arr[3] = d;
     return *(unsigned int *)arr;
}

#endif