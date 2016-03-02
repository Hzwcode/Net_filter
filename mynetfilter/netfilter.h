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

#define ANY_ADDR 0
#define ANY_PORT 0xffff
#define ANY_PROTOCOL 0xffff

#define MASK_IP(x, mask) (x & (0xffffffff << (32 - mask)))

typedef struct rule_time{
     struct rtc_time begin_time;
     struct rtc_time end_time;
     Bool valid;
}RULE_TIME; 

//规则
typedef struct rule{
     struct{
          uint32_t addr;        //IP地址
          uint8_t mask;         //掩码
     }s_addr, d_addr;           //源IP地址，目的IP地址
	uint16_t s_port, d_port;   //源端口，目的端口
	__u8 protocol;             //协议类型                      
     RULE_TIME tm;              //时间段
	Bool action;               //动作

     struct rule *next;         //下一结点域
}RULE;

unsigned int hook_pre_routing(unsigned int hooknum,
                         struct sk_buff *skb,
                         const struct net_device *in,
                         const struct net_device *out,
                         int (*okfn)(struct sk_buff *));

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

unsigned int hook_local_out(unsigned int hooknum,
                         struct sk_buff *skb,
                         const struct net_device *in,
                         const struct net_device *out,
                         int (*okfn)(struct sk_buff *));

unsigned int hook_post_routing(unsigned int hooknum,
                         struct sk_buff *skb,
                         const struct net_device *in,
                         const struct net_device *out,
                         int (*okfn)(struct sk_buff *));


#endif