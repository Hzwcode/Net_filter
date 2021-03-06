/*  
 ** 安装一个丢弃所有到达的数据包的Netfilter hook函数的示例代码  
 **/
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
 
#include "netfilter.h"
#include "chardev.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("shsf_hzw");

struct rule rule_pre_routing;
struct rule rule_local_out;

static struct nf_hook_ops nfho_pre_routing;         //负责发往本机的报文和路由穿过本机的报文
//static struct nf_hook_ops nfho_local_in;
//static struct nf_hook_ops nfho_forward;
static struct nf_hook_ops nfho_local_out;           //负责本机发出去的报文
//static struct nf_hook_ops nfho_post_routing;

int init_rule_list(void)
{
    INIT_LIST_HEAD(&(rule_pre_routing.list));
    INIT_LIST_HEAD(&(rule_local_out.list));
    return 0;
}

void destroy_rule_list(void){
    struct rule *tmp = NULL;
    struct list_head *pos = NULL, *p = NULL;

    list_for_each_safe(pos, p, &rule_pre_routing.list){
        tmp = list_entry(pos, struct rule, list);
        list_del(pos);
        kfree(tmp);
    }

    list_for_each_safe(pos, p, &rule_local_out.list){
        tmp = list_entry(pos, struct rule, list);
        list_del(pos);
        kfree(tmp);
    }
}

void nf_pre_routing_init(void)
{
    nfho_pre_routing.hook = (nf_hookfn*)hook_pre_routing;
    nfho_pre_routing.owner = NULL;
    nfho_pre_routing.pf = PF_INET;
    nfho_pre_routing.hooknum = NF_INET_PRE_ROUTING;
    nfho_pre_routing.priority=NF_IP_PRI_FIRST;

    nf_register_hook(&nfho_pre_routing);// 注册一个钩子函数
}
/*
void nf_local_in_init(void)
{
    nfho_local_in.hook = (nf_hookfn*)hook_local_in;
    nfho_local_in.owner = NULL;
    nfho_local_in.pf = PF_INET;
    nfho_local_in.hooknum = NF_INET_LOCAL_IN;
    nfho_local_in.priority=NF_IP_PRI_FIRST;

    nf_register_hook(&nfho_local_in);// 注册一个钩子函数
}

void nf_forward_init(void)
{
    nfho_forward.hook = (nf_hookfn*)hook_forward;
    nfho_forward.owner = NULL;
    nfho_forward.pf = PF_INET;
    //nfho.hooknum = NF_INET_LOCAL_OUT;
    nfho_forward.hooknum = NF_INET_FORWARD;
    nfho_forward.priority=NF_IP_PRI_FIRST;

    nf_register_hook(&nfho_forward);// 注册一个钩子函数
}
*/
void nf_local_out_init(void)
{
    nfho_local_out.hook = (nf_hookfn*)hook_local_out;
    nfho_local_out.owner = NULL;
    nfho_local_out.pf = PF_INET;
    nfho_local_out.hooknum = NF_INET_LOCAL_OUT;
    nfho_local_out.priority=NF_IP_PRI_FIRST;

    nf_register_hook(&nfho_local_out);// 注册一个钩子函数
}
/*
void nf_post_routing_init(void)
{
    nfho_post_routing.hook = (nf_hookfn*)hook_post_routing;
    nfho_post_routing.owner = NULL;
    nfho_post_routing.pf = PF_INET;
    nfho_post_routing.hooknum = NF_INET_POST_ROUTING;
    nfho_post_routing.priority=NF_IP_PRI_FIRST;

    nf_register_hook(&nfho_post_routing);// 注册一个钩子函数
}
*/
static int kexec_test_init(void)
{
    printk("Init: kexec test start... \n");
    nf_pre_routing_init();
    //nf_local_in_init();
    //nf_forward_init();
    nf_local_out_init();
    //nf_post_routing_init();

    if(init_rule_list() != 0){
        printk("init rule list failed!!!\n");
        return -1;
    }

    dev_init();
    return 0;
}

static void kexec_test_exit(void)
{
    printk("Exit: kexec test exit ...\n");
    nf_unregister_hook(&nfho_pre_routing);
    //nf_unregister_hook(&nfho_local_in);
    //nf_unregister_hook(&nfho_forward);
    nf_unregister_hook(&nfho_local_out);
    //nf_unregister_hook(&nfho_post_routing);
    destroy_rule_list();

    dev_exit();
}

module_init(kexec_test_init);
module_exit(kexec_test_exit);

