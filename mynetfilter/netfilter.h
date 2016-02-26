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
#define ANY_PROROCOL 0xffff
#define ANY_TIME 0


typedef struct rule{
     struct{
          uint32_t addr;
          uint8_t mask;
     }s_addr, d_addr;
	uint16_t s_port, d_port;
	__be16 protocal;
	struct{
          ktime_t begin_time;
          ktime_t end_time;
     }tm;
	Bool action;

     struct rule *next;
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