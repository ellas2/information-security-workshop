#include <linux/string.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <linux/module.h>    
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/device.h>
#include <linux/fs.h>
#include "fw.h"
#include "fw_rules.h"
#include "fw_log.h"

#define MAJOR_NUM 250;

MODULE_LICENSE("GPL");
static struct class* rules_logs_class = NULL;
static struct device* rules_device = NULL;
static struct device* logs_device = NULL;
static struct nf_hook_ops nf_forward;
static int major_num = MAJOR_NUM;

unsigned int hook_func_forward(unsigned int hooknum, struct sk_buff *skb,
 		const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)){
	//get src address, src netmask, src port, dest ip, dest netmask, dest port, protocol
   direction_t direction;
   int i;
   unsigned long curr_time;
   struct timeval time;
   struct iphdr *ip_header;
   struct udphdr *udp_header;
   struct tcphdr *tcp_header;
   do_gettimeofday(&time);
   curr_time = (u32)(time.tv_sec - ((sys_tz.tz_minuteswest + 120)* 60));
   ip_header = (struct iphdr *)skb_network_header(skb);
   //get src and dest ip addresses
   unsigned int src_ip = (unsigned int)ip_header->saddr;
   unsigned int dst_ip = (unsigned int)ip_header->daddr;
   unsigned int src_port = PORT_ANY;
   unsigned int dst_port = PORT_ANY;
   ack_t ack = ACK_ANY;//will only be relevant for TCP
   //get src and dest port number
   if (ip_header->protocol == PROT_UDP){
       udp_header = (struct udphdr *)skb_transport_header(skb);
  	   src_port = (unsigned int)ntohs(udp_header->source);
       dst_port = (unsigned int)ntohs(udp_header->dest);
   } else if (ip_header->protocol == PROT_TCP){
       tcp_header = (struct tcphdr *)skb_transport_header(skb);
       src_port = (unsigned int)ntohs(tcp_header->source);
       dst_port = (unsigned int)ntohs(tcp_header->dest);
       ack = (unsigned long)ntohl(tcp_header->ack);
       //xmas tree
       if ((tcp_header->fin == 1) && (tcp_header->urg == 1) && (tcp_header->psh == 1)){
       		if((add_to_logs(curr_time, PROT_TCP, NF_DROP, 
 				hooknum, src_ip, dst_ip, src_port, dst_port, REASON_XMAS_PACKET)) != 0){
       			printk("Unable to add to log\n");
       		}
   			return NF_DROP;
       }
       
   } else{//not UDP or TCP - can be ICMP or any other protocol
      	src_port = PORT_ANY;
   		dst_port = PORT_ANY;
	}
   //get direction
	if (out != NULL)
		direction = DIRECTION_OUT;
	else if (in != NULL)
		direction = DIRECTION_IN;
	else{//invalid
		if ((add_to_logs(curr_time, ip_header->protocol, NF_DROP, 
   				hooknum, src_ip, dst_ip, src_port, dst_port, REASON_ILLEGAL_VALUE)) != 0){
			printk("Unable to add to log\n");
		}
   		return NF_DROP;
	}
   //FW is down - no need to check the rules - 
   //just add to logs with the reason REASON_FW_INACTIVE and accept the packet
   if (!(is_fw_active())){
   		if ((add_to_logs(curr_time, ip_header->protocol, NF_ACCEPT, 
   			hooknum, src_ip, dst_ip, src_port, dst_port, REASON_FW_INACTIVE)) != 0){
   			printk("Unable to add to log\n");
   		}
   		return NF_ACCEPT;
   }

   //go over the rules and look for a match -
   //if a match is found - register in logs and then "decide"
   for(i = 0; i < num_rules(); i++){
   		//if a match is found - decide according to action in rule table
   		if (compare_to_rule(i, direction, src_ip, dst_ip, ip_header->protocol, 
   			ack, src_port, dst_port) == 0){
   			if ((add_to_logs(curr_time, ip_header->protocol, rules[i].action, 
   					hooknum, src_ip, dst_ip, src_port, dst_port, i)) != 0){
   				printk("Unable to add to log\n");
   			}
   			return rules[i].action;
   		}
   }
   //no matching rule found - 
   //add to logs that the packet has been accepted and accept it!
   	if ((add_to_logs(curr_time, ip_header->protocol, NF_ACCEPT, 
   				hooknum, src_ip, dst_ip, src_port, dst_port, 
   				REASON_NO_MATCHING_RULE)) != 0){
   		printk("Unable to add to log\n");
   	}
	return NF_ACCEPT;
 }

static struct file_operations fops = {
	.owner = THIS_MODULE,
	.read = my_read_for_show_logs,
	.open = my_open_for_show_logs
};

static DEVICE_ATTR(log_size, S_IROTH , display_log_size, NULL);
static DEVICE_ATTR(rules_size, S_IROTH , display_rules_size, NULL);
static DEVICE_ATTR(log_clear, S_IWOTH , NULL, modify_log_clear);
static DEVICE_ATTR(active, S_IRWXO , display_active, modify_active);
static DEVICE_ATTR(clear_rules, S_IWOTH , NULL, modify_clear_rules);
static DEVICE_ATTR(show_rules, S_IROTH , display_show_rules, NULL);
static DEVICE_ATTR(load_rules, S_IWOTH , NULL, modify_load_rules);


static int __init my_module_init_function(void){
	make_localhost_rule();
	//registering the hook function 
	nf_forward.hook = hook_func_forward;
	nf_forward.hooknum = NF_INET_FORWARD;
	nf_forward.pf = PF_INET;
	nf_forward.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&nf_forward);
	//setting up the rules and log devices
	if ((register_chrdev(major_num, "rules_and_logs", &fops)) < 0)
		return -1;
	rules_logs_class = class_create(THIS_MODULE, CLASS_NAME);
	if (IS_ERR(rules_logs_class)){
		class_destroy(rules_logs_class);			
		unregister_chrdev(major_num, "rules_and_logs");
		return -1;
	}
	rules_device = device_create(rules_logs_class, NULL, MKDEV(major_num, MINOR_RULES), NULL, CLASS_NAME "_" DEVICE_NAME_RULES);	
	if (IS_ERR(rules_device)){
		class_destroy(rules_logs_class);
		unregister_chrdev(major_num, "rules_and_logs");
		return -1;
	}
	logs_device = device_create(rules_logs_class, NULL, MKDEV(major_num, MINOR_LOG), NULL, CLASS_NAME "_" DEVICE_NAME_LOG);
	if (IS_ERR(logs_device)){
		class_destroy(rules_logs_class);
		unregister_chrdev(major_num, "rules_and_logs");
		return -1;
	}
	//sysfs device file for logs size
	if (device_create_file(logs_device, (const struct device_attribute *)&dev_attr_log_size.attr)){
		device_destroy(rules_logs_class, MKDEV(major_num, MINOR_LOG));
		class_destroy(rules_logs_class);
		unregister_chrdev(major_num, "rules_and_logs");
		return -1;
	}
	//sysfs device file for rules size
	if (device_create_file(rules_device, (const struct device_attribute *)&dev_attr_rules_size.attr)){
		device_destroy(rules_logs_class, MKDEV(major_num, MINOR_RULES));
		class_destroy(rules_logs_class);
		unregister_chrdev(major_num, "rules_and_logs");
		return -1;
	}
	//sysfs device file for clear logs
	if (device_create_file(logs_device, (const struct device_attribute *)&dev_attr_log_clear.attr))
	{
		device_destroy(rules_logs_class, MKDEV(major_num, MINOR_LOG));
		class_destroy(rules_logs_class);
		unregister_chrdev(major_num, "rules_and_logs");
		return -1;
	}
	//sysfs device file for active
	if (device_create_file(rules_device, (const struct device_attribute *)&dev_attr_active.attr)){
		device_destroy(rules_logs_class, MKDEV(major_num, MINOR_RULES));
		class_destroy(rules_logs_class);
		unregister_chrdev(major_num, "rules_and_logs");
		return -1;
	}
	//sysfs device file for clearing rules
	if (device_create_file(rules_device, (const struct device_attribute *)&dev_attr_clear_rules.attr)){
		device_destroy(rules_logs_class, MKDEV(major_num, MINOR_RULES));
		class_destroy(rules_logs_class);
		unregister_chrdev(major_num, "rules_and_logs");
		return -1;
	}
	//sysfs device file for showing rules
	if (device_create_file(rules_device, (const struct device_attribute *)&dev_attr_show_rules.attr)){
		device_destroy(rules_logs_class, MKDEV(major_num, MINOR_RULES));
		class_destroy(rules_logs_class);
		unregister_chrdev(major_num, "rules_and_logs");
		return -1;
	}
	//sysfs device file for loading rules
	if (device_create_file(rules_device, (const struct device_attribute *)&dev_attr_load_rules.attr)){
		device_destroy(rules_logs_class, MKDEV(major_num, MINOR_RULES));
		class_destroy(rules_logs_class);
		unregister_chrdev(major_num, "rules_and_logs");
		return -1;
	}
	

	return 0;
}

static void __exit my_module_exit_function(void){
	kfree(logs_str);
	kfree(logs);
	device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_load_rules.attr);
	device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_show_rules.attr);
	device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_clear_rules.attr);
	device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_active.attr);
	device_remove_file(logs_device, (const struct device_attribute *)&dev_attr_log_clear.attr);
	device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_rules_size.attr);
	device_remove_file(logs_device, (const struct device_attribute *)&dev_attr_log_size.attr);
	device_destroy(rules_logs_class, MKDEV(major_num, MINOR_LOG));
	device_destroy(rules_logs_class, MKDEV(major_num, MINOR_RULES));
	class_destroy(rules_logs_class);
	unregister_chrdev(major_num, "rules_and_logs");
	nf_unregister_hook(&nf_forward);
}


module_init(my_module_init_function);
module_exit(my_module_exit_function);