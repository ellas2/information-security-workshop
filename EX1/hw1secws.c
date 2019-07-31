#include <linux/module.h>    
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

MODULE_LICENSE("GPL");

static struct nf_hook_ops nf_local_in;
static struct nf_hook_ops nf_local_out;
static struct nf_hook_ops nf_forward;

//the hook function for local incoming packets
unsigned int hook_func_in(unsigned int hooknum, struct sk_buff *skb,
 		const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)){
	printk(KERN_INFO "*** packet passed ***");
	return NF_ACCEPT;

 }


//the hook function for local outgoing packets
unsigned int hook_func_out(unsigned int hooknum, struct sk_buff *skb,
 		const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)){
	printk(KERN_INFO "*** packet passed ***");
	return NF_ACCEPT;

 }

 //the hook function for local outgoing packets
unsigned int hook_func_forward(unsigned int hooknum, struct sk_buff *skb,
 		const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)){
	printk(KERN_INFO "*** packet blocked ***");
	return NF_DROP;

 }

static int __init my_module_init_function(void){
	//filling in the hook struct for local incoming packets
	nf_local_in.hook = hook_func_in;
	nf_local_in.hooknum = NF_INET_LOCAL_IN;
	nf_local_in.pf = PF_INET;
	nf_local_in.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&nf_local_in);
	//filling in the hook struct for local outgoing packets
	nf_local_out.hook = hook_func_out;
	nf_local_out.hooknum = NF_INET_LOCAL_OUT;
	nf_local_out.pf = PF_INET;
	nf_local_out.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&nf_local_out);
	//filling in the hook struct for local outgoing packets
	nf_forward.hook = hook_func_forward;
	nf_forward.hooknum = NF_INET_FORWARD;
	nf_forward.pf = PF_INET;
	nf_forward.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&nf_forward);
	return 0; 
}

static void __exit my_module_exit_function(void){
	nf_unregister_hook(&nf_local_in);
	nf_unregister_hook(&nf_local_out);
	nf_unregister_hook(&nf_forward);
}


module_init(my_module_init_function);
module_exit(my_module_exit_function);