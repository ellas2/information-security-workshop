#include <linux/string.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <linux/module.h>    
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/device.h>
#include <linux/fs.h>
#include "fw_log.h"


static char* logs_str_buffer_ind;
static int logs_str_len;
static unsigned int log_size = 0;

clear_log(){
	log_size = 0;
	kfree(logs);
}

unsigned int ip_str_to_hl_2(char* ip_str){
	//convert the string to byte array first, e.g.: from "131.132.162.25" to [131][132][162][25]
    unsigned char ip_array[4];
    int i = 0;
    unsigned int ip;
    ip = 0;
    if (ip_str == NULL)
        return 0; 
    memset(ip_array, 0, 4);
    while (ip_str[i] != '.'){
        ip_array[0] = ip_array[0]*10 + (ip_str[i++]-'0');
    }
    ++i;
    while (ip_str[i] != '.') {
        ip_array[1] = ip_array[1]*10 + (ip_str[i++]-'0');
    }
    ++i;
    while (ip_str[i] != '.') {
        ip_array[2] = ip_array[2]*10 + (ip_str[i++]-'0');
    }
    ++i;
    while (ip_str[i] != '\0') {
        ip_array[3] = ip_array[3]*10 + (ip_str[i++]-'0');
    }
    /*convert from byte array to host long integer format*/
    ip = (ip_array[0] << 24);
    ip = (ip | (ip_array[1] << 16));
    ip = (ip | (ip_array[2] << 8));
    ip = (ip | ip_array[3]);
    //printk(KERN_INFO "ip_str_to_hl convert %s to %un", ip_str, ip);
    return ip;
}

//compares a single log row to another - 
//returns 0 for similar and 1 for different
int compare_single_log_row(int ind, unsigned char protocol,
	unsigned char action, unsigned char hooknum, __be32 src_ip, 
	__be32 dst_ip, __be16 src_port, __be16 dst_port,
	reason_t reason){
	if (logs[ind].protocol != protocol)
		return 1;
	else if (logs[ind].action != action)
		return 1;
	else if (logs[ind].hooknum != hooknum)
		return 1;
	else if (logs[ind].src_ip != src_ip)
		return 1;
	else if (logs[ind].dst_ip != dst_ip)
		return 1;
	else if (logs[ind].src_port != src_port)
		return 1;
	else if (logs[ind].dst_port != dst_port)
		return 1;
	else if (logs[ind].reason != reason)
		return 1;
	//nothing different found - similar log rows 
	return 0;
}

int add_new_log_row(unsigned long timestamp, unsigned char protocol,
	unsigned char action, unsigned char hooknum, __be32 src_ip, 
	__be32 dst_ip, __be16 src_port, __be16 dst_port, reason_t reason){
	//if logs are empty we need to allocate the memory
	if (log_size == 0){
		
		//logs = (log_row_t*)kmalloc(sizeof(log_row_t), GFP_KERNEL);
		logs = (log_row_t*)kmalloc(sizeof(log_row_t), GFP_ATOMIC);
		if (logs == NULL){
			return -ENOMEM;
		}
	//if logs already exist we need to reallocate the memory
	} else{
		log_row_t* new_logs = krealloc(logs,(log_size+1)*sizeof(log_row_t), GFP_ATOMIC);
		if (new_logs == NULL){
			kfree(logs);
			return -ENOMEM;
		}
		logs = new_logs;
	}
	logs[log_size].timestamp = timestamp;
	logs[log_size].protocol = protocol;
	logs[log_size].action = action;
	logs[log_size].hooknum = hooknum;
	logs[log_size].src_ip = src_ip;
	logs[log_size].dst_ip = dst_ip;
	logs[log_size].src_port = src_port;
	logs[log_size].dst_port = dst_port;
	logs[log_size].reason = reason;
	logs[log_size].count = 1;
	log_size++;
	return 0;
}

//go over the log rows
//if there is a log row that fits the passed values - 
//count++ and update it with the new timestamp
//otherwise - add a new one
int add_to_logs(unsigned long timestamp, unsigned char protocol,
	unsigned char action, unsigned char hooknum, __be32 src_ip, 
	__be32 dst_ip, __be16 src_port, __be16 dst_port, reason_t reason){
	if (src_ip == ip_str_to_hl_2("127.0.0.1"))//localhost packet shouldn't be logged
		return 0;
	int i;
	for (i = 0; i < log_size; i++){
		if (compare_single_log_row(i, protocol, action, hooknum, src_ip, 
			dst_ip, src_port, dst_port, reason) == 0){
			logs[i].count++;//enlarge count by one
			logs[i].timestamp = timestamp;//update the timestamp
			return 0;//don't keep looking
		}
	}
	//no log row found - add a new one
	if ((add_new_log_row(timestamp, protocol, action, hooknum, src_ip, dst_ip, 
		src_port, dst_port, reason)) != 0){
		return -1;
	}
	return 0;
}



void create_log_str(){
	//we want to construct the logs 
	char timestamp_str[10], protocol_str[3], action_str[2], hooknum_str[3];
	char src_ip_str[11], dst_ip_str[11], src_port_str[5], dst_port_str[5];
	char reason_str[2], count_str[5];
	int i;
	logs_str = NULL;
	logs_str = (char*)kmalloc(70*log_size, GFP_ATOMIC);
	logs_str[0] = '\0';
	for (i = 0; i < log_size; i++){
		sprintf(timestamp_str, "%lu", logs[i].timestamp);
		strcat(logs_str, timestamp_str);
		strcat(logs_str, " ");
		sprintf(protocol_str, "%hhu", logs[i].protocol);
		strcat(logs_str, protocol_str);
		strcat(logs_str, " ");
		sprintf(action_str, "%hhu", logs[i].action);
		strcat(logs_str, action_str);
		strcat(logs_str, " ");
		sprintf(hooknum_str, "%hhu", logs[i].hooknum);
		strcat(logs_str, hooknum_str);
		strcat(logs_str, " ");
		sprintf(src_ip_str, "%u", logs[i].src_ip);
		strcat(logs_str, src_ip_str);
		strcat(logs_str, " ");
		sprintf(dst_ip_str, "%u", logs[i].dst_ip);
		strcat(logs_str, dst_ip_str);
		strcat(logs_str, " ");
		sprintf(src_port_str, "%hu", logs[i].src_port);
		strcat(logs_str, src_port_str);
		strcat(logs_str, " ");
		sprintf(dst_port_str, "%hu", logs[i].dst_port);
		strcat(logs_str, dst_port_str);
		strcat(logs_str, " ");
		sprintf(reason_str, "%d", logs[i].reason);
		strcat(logs_str, reason_str);
		strcat(logs_str, " ");
		sprintf(count_str, "%u", logs[i].count);
		strcat(logs_str, count_str);
		strcat(logs_str, "\n");
	}
}

int my_open_for_show_logs(struct inode *_inode, struct file *_file){
	create_log_str();
	logs_str_len = strlen(logs_str);
	logs_str_buffer_ind = logs_str;
	return 0;
}

ssize_t my_read_for_show_logs(struct file *filp, char *buff, size_t length, loff_t *offp){
	ssize_t num_of_bytes;
	int retval;
	num_of_bytes = (logs_str_len < length) ? logs_str_len : length;
	if (num_of_bytes == 0)
		return 0;
	if (copy_to_user(buff, logs_str_buffer_ind, num_of_bytes))
		return -EFAULT;
	else{
		logs_str_len -= num_of_bytes;
		logs_str_buffer_ind += num_of_bytes;
		return num_of_bytes;
	}
	return -EFAULT;
}


ssize_t display_log_size(struct device *dev, struct device_attribute *attr, char *buf){
	return scnprintf(buf, PAGE_SIZE, "%u\n", log_size);
}


ssize_t modify_log_clear(struct device *dev, struct device_attribute *attr, const char *buf, size_t count){	//sysfs store implementation{
	int temp;
	if (sscanf(buf, "%u", &temp) == 1){
		clear_log();
	}
	return count;	
}


