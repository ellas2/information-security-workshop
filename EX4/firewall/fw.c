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
#include "fw_con_table.h"
#include "fw_netfilter.h"

MODULE_LICENSE("GPL");

static struct class* rules_logs_class = NULL;
static struct device* rules_device = NULL;
static struct device* logs_device = NULL;

static int major_num;


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


int init_module(void){
	make_localhost_rule();
	netfilter_init();
	//setting up the rules and log devices
	if ( (major_num = (register_chrdev(0, CLASS_NAME "_" DEVICE_NAME_LOG, &fops))) < 0){
		return -1;
	}
	rules_logs_class = class_create(THIS_MODULE, CLASS_NAME);
	if (IS_ERR(rules_logs_class)){
		class_destroy(rules_logs_class);			
		unregister_chrdev(major_num, CLASS_NAME "_" DEVICE_NAME_LOG);
		return -1;
	}
	rules_device = device_create(rules_logs_class, NULL, MKDEV(major_num, MINOR_RULES), NULL, CLASS_NAME "_" DEVICE_NAME_RULES);	
	if (IS_ERR(rules_device)){
		class_destroy(rules_logs_class);
		unregister_chrdev(major_num, CLASS_NAME "_" DEVICE_NAME_LOG);
		return -1;
	}
	logs_device = device_create(rules_logs_class, NULL, MKDEV(major_num, MINOR_LOG), NULL, CLASS_NAME "_" DEVICE_NAME_LOG);
	if (IS_ERR(logs_device)){
		class_destroy(rules_logs_class);
		unregister_chrdev(major_num, CLASS_NAME "_" DEVICE_NAME_LOG);
		return -1;
	}
	//sysfs device file for logs size
	if (device_create_file(logs_device, (const struct device_attribute *)&dev_attr_log_size.attr)){
		device_destroy(rules_logs_class, MKDEV(major_num, MINOR_LOG));
		class_destroy(rules_logs_class);
		unregister_chrdev(major_num, CLASS_NAME "_" DEVICE_NAME_LOG);
		return -1;
	}
	//sysfs device file for rules size
	if (device_create_file(rules_device, (const struct device_attribute *)&dev_attr_rules_size.attr)){
		device_destroy(rules_logs_class, MKDEV(major_num, MINOR_RULES));
		class_destroy(rules_logs_class);
		unregister_chrdev(major_num, CLASS_NAME "_" DEVICE_NAME_LOG);
		return -1;
	}
	//sysfs device file for clear logs
	if (device_create_file(logs_device, (const struct device_attribute *)&dev_attr_log_clear.attr)){
		device_destroy(rules_logs_class, MKDEV(major_num, MINOR_LOG));
		class_destroy(rules_logs_class);
		unregister_chrdev(major_num, CLASS_NAME "_" DEVICE_NAME_LOG);
		return -1;
	}
	//sysfs device file for active
	if (device_create_file(rules_device, (const struct device_attribute *)&dev_attr_active.attr)){
		device_destroy(rules_logs_class, MKDEV(major_num, MINOR_RULES));
		class_destroy(rules_logs_class);
		unregister_chrdev(major_num, CLASS_NAME "_" DEVICE_NAME_LOG);
		return -1;
	}
	//sysfs device file for clearing rules
	if (device_create_file(rules_device, (const struct device_attribute *)&dev_attr_clear_rules.attr)){
		device_destroy(rules_logs_class, MKDEV(major_num, MINOR_RULES));
		class_destroy(rules_logs_class);
		unregister_chrdev(major_num, CLASS_NAME "_" DEVICE_NAME_LOG);
		return -1;
	}
	//sysfs device file for showing rules
	if (device_create_file(rules_device, (const struct device_attribute *)&dev_attr_show_rules.attr)){
		device_destroy(rules_logs_class, MKDEV(major_num, MINOR_RULES));
		class_destroy(rules_logs_class);
		unregister_chrdev(major_num, CLASS_NAME "_" DEVICE_NAME_LOG);
		return -1;
	}
	//sysfs device file for loading rules
	if (device_create_file(rules_device, (const struct device_attribute *)&dev_attr_load_rules.attr)){
		device_destroy(rules_logs_class, MKDEV(major_num, MINOR_RULES));
		class_destroy(rules_logs_class);
		unregister_chrdev(major_num, CLASS_NAME "_" DEVICE_NAME_LOG);
		return -1;
	}
	if (init_con_table_devices(rules_logs_class, major_num) == -1){
		return -1;
	}
	
	return 0;
}
	

void cleanup_module(void){
	kfree(logs_str);
	kfree(logs);
	kfree(conn_table_str);
	kfree(conn_table);
	cleanup_con_table_devices(rules_logs_class, major_num);
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
	unregister_chrdev(major_num, "fw_log");
	netfilter_cleanup();
}
