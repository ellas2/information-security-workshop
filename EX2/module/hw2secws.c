#include <linux/module.h>    
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/device.h>
#include <linux/fs.h>
MODULE_LICENSE("GPL");

static int pairity = 0;
static int num_accepted = 0;
static int num_dropped = 0;
static int major_num;
static struct class* sysfs_class = NULL;
static struct device* sysfs_device = NULL;

static struct file_operations fops = {
	.owner = THIS_MODULE
};

ssize_t display(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show implementation
{
	pairity = !pairity;
	if(pairity)
		return scnprintf(buf, PAGE_SIZE, "%u\n", num_accepted);
	return scnprintf(buf, PAGE_SIZE, "%u\n", num_dropped);
}

ssize_t modify(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	//sysfs store implementation
{
	int temp;
	if (sscanf(buf, "%u", &temp) == 1 && temp == 0){// we do not want to allow changing the value to anything else! 
		num_accepted = temp;
		num_dropped = temp;
	}
	return count;	
}

static struct nf_hook_ops nf_local_in;
static struct nf_hook_ops nf_local_out;
static struct nf_hook_ops nf_forward;

//the hook function for local incoming packets
unsigned int hook_func_in(unsigned int hooknum, struct sk_buff *skb,
 		const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)){
	num_accepted++;
	printk(KERN_INFO "*** packet passed ***");
	return NF_ACCEPT;

 }

//the hook function for local outgoing packets
unsigned int hook_func_out(unsigned int hooknum, struct sk_buff *skb,
 		const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)){
	num_accepted++;
	printk(KERN_INFO "*** packet passed ***");
	return NF_ACCEPT;

 }

 //the hook function for local outgoing packets
unsigned int hook_func_forward(unsigned int hooknum, struct sk_buff *skb,
 		const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)){
	num_dropped++;
	printk(KERN_INFO "*** packet blocked ***");
	return NF_DROP;

 }

static DEVICE_ATTR(sysfs_att, S_IRWXO , display, modify);

static int __init my_module_init_function(void){
	printk(KERN_INFO "initializing module");
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

	//create char device
	major_num = register_chrdev(0, "sysfs_device", &fops);
	if (major_num < 0)
		return -1;	
	//create sysfs class
	sysfs_class = class_create(THIS_MODULE, "sysfs_class");
	if (IS_ERR(sysfs_class))
	{
		unregister_chrdev(major_num, "sysfs_device");
		return -1;
	}
	
	//create sysfs device
	sysfs_device = device_create(sysfs_class, NULL, MKDEV(major_num, 0), NULL, "sysfs_class" "_" "sysfs_device");	
	if (IS_ERR(sysfs_device))
	{
		class_destroy(sysfs_class);
		unregister_chrdev(major_num, "sysfs_device");
		return -1;
	}
	//create sysfs file attributes	
	if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_sysfs_att.attr))
	{
		device_destroy(sysfs_class, MKDEV(major_num, 0));
		class_destroy(sysfs_class);
		unregister_chrdev(major_num, "sysfs_device");
		return -1;
	}
	return 0; 
}

static void __exit my_module_exit_function(void){
	nf_unregister_hook(&nf_local_in);
	nf_unregister_hook(&nf_local_out);
	nf_unregister_hook(&nf_forward);

	device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_sysfs_att.attr);
	device_destroy(sysfs_class, MKDEV(major_num, 0));
	class_destroy(sysfs_class);
	unregister_chrdev(major_num, "sysfs_device");
	printk(KERN_INFO "module unloaded");
}


module_init(my_module_init_function);
module_exit(my_module_exit_function);
