#include <linux/string.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <linux/module.h>    
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/device.h>
#include <linux/fs.h>
#include "fw_rules.h"

static unsigned int active = 0;
static unsigned int rules_size = 1;

unsigned int prefix_size_to_mask(unsigned char prefix_size){
	return ((0xFFFFFFFF << (32 - prefix_size)) & 0xFFFFFFFF);
}


unsigned int ip_str_to_hl(char* ip_str){
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


void make_localhost_rule(void){
	//(rules[0].rule_name)[0] = '\0';
	strcpy((rules[0].rule_name), "Localhost");
	rules[0].direction = DIRECTION_ANY;
	unsigned int localhost_ip = ip_str_to_hl("127.0.0.1");
	rules[0].src_ip = localhost_ip;
	rules[0].src_prefix_mask = prefix_size_to_mask(8);
	rules[0].src_prefix_size = 8;
	rules[0].dst_ip = localhost_ip;
	rules[0].dst_prefix_mask = prefix_size_to_mask(8);
	rules[0].dst_prefix_size = 8;
	rules[0].src_port = PORT_ANY;
	rules[0].dst_port = PORT_ANY;
	rules[0].protocol = PROT_ANY;
	rules[0].ack = ACK_ANY;
	rules[0].action = 1;
}

int num_rules(void){
	return rules_size;
}

int is_fw_active(){
	if (active == 1)
		return 1;
	return 0;
}

//check the two input IP addresses, see if they match, only the first few bits (masked bits) are compared
int check_ip(unsigned int ip, unsigned int ip_rule, unsigned int mask) {
    unsigned int tmp = ntohl(ip);    //network to host long
    int cmp_len = 32;
    int i = 0, j = 0;
    if (mask != 0) {
       cmp_len = 0;
       for (i = 0; i < 32; ++i) {
      if (mask & (1 << (32-1-i)))
         cmp_len++;
      else
         break;
       }
    }
    //compare the two IP addresses for the first cmp_len bits
    for (i = 31, j = 0; j < cmp_len; --i, ++j) {
        if ((tmp & (1 << i)) != (ip_rule & (1 << i))) {
            //printk(KERN_INFO "ip compare: %d bit doesn't matchn", (32-i));
            return 1;
        }
    }
    return 0;
}


int compare_to_rule(int ind, direction_t direction, unsigned long src_ip, unsigned long dst_ip,
	prot_t protocol, ack_t ack, unsigned short src_port, unsigned short dst_port){
	printk("comparing with rule number %d\n", ind);
	//check direction
	if ((rules[ind].direction != DIRECTION_ANY) && (rules[ind].direction != direction)){
		printk("direction mismatch");
		return 1;
	}
	//rules[ind].src_ip = 0 means that it is "ANY"
	//check the src ip with src mask
	else if ((rules[ind].src_ip != 0) && (check_ip(src_ip, rules[ind].src_ip, rules[ind].src_prefix_mask) != 0)){
		printk("src_ip mismatch");
		return 1;
	}
	//rules[ind].dst_ip = 0 means that it is "ANY"
	//check the dst ip with dst mask
	else if ((rules[ind].dst_ip != 0) && (check_ip(dst_ip, rules[ind].dst_ip, rules[ind].dst_prefix_mask) != 0)){
		printk("dst_ip mismatch");
		return 1;
	}
	//check the protocol
	else if ((rules[ind].protocol != PROT_ANY) && (rules[ind].protocol != protocol)){
		printk("protocol mismatch");
		return 1;	
	}
	else if (protocol == PROT_TCP || protocol == PROT_UDP){
		//if tcp - check ack (otherwise ack is irrelevant)
		if ((protocol == PROT_TCP) && (rules[ind].ack != ACK_ANY) && (rules[ind].ack != ack))
			return 1;
		//src_port
		if (rules[ind].src_port != PORT_ANY){
			if ((rules[ind].src_port == PORT_ABOVE_1023) && (src_port <= 1023)){
				printk("src_port mismatch");
				return 1;
			}
			else if (rules[ind].src_port != src_port){
				printk("src_port mismatch");
				return 1;
			}
		}
		if (rules[ind].dst_port != PORT_ANY){
			if ((rules[ind].dst_port == PORT_ABOVE_1023) && (dst_port <= 1023)){
				printk("src_port mismatch");
				return 1;
			}
			else if(rules[ind].dst_port != dst_port){
				printk("src_port mismatch");
				return 1;
			}
		}
	}
	//everything matched 
	return 0;
}



ssize_t display_rules_size(struct device *dev, struct device_attribute *attr, char *buf){
	return scnprintf(buf, PAGE_SIZE, "%u\n", rules_size);
}

ssize_t display_active(struct device *dev, struct device_attribute *attr, char *buf){
	return scnprintf(buf, PAGE_SIZE, "%u\n", active);
}

ssize_t modify_active(struct device *dev, struct device_attribute *attr, const char *buf, size_t count){	//sysfs store implementation{
	int temp;
	if ((sscanf(buf, "%u", &temp) == 1) && ((temp == 0) || (temp == 1))){//other values are ignored here - tested at the user's side
		active = temp;
	}

	return count;	
}


ssize_t modify_clear_rules(struct device *dev, struct device_attribute *attr, const char *buf, size_t count){	//sysfs store implementation{
	int temp;
	if ((sscanf(buf, "%u", &temp) == 1) && (temp == 0)){//other values are ignored here - tested at the user's side
		rules_size = 1;//we always have the localhost rule
		//I always work with rules_size so all the rest of the rules are "garbage" - 
		//I did not "nullify" them here
	}
	return count;	
}


ssize_t modify_load_rules(struct device *dev, struct device_attribute *attr, const char *buf, size_t count){	//sysfs store implementation{
	//we load one rule every time - to the last place available
	if (sscanf(buf, "%s %x %u/%hhu %u/%hhu %hhu %hu %hu %x %hhu %u %u\n",
		rules[rules_size].rule_name,
		&(rules[rules_size].direction), 
		&(rules[rules_size].src_ip), 
		&(rules[rules_size].src_prefix_size), 
		&(rules[rules_size].dst_ip), 
		&(rules[rules_size].dst_prefix_size), 
		&(rules[rules_size].protocol),
		&(rules[rules_size].src_port),
		&(rules[rules_size].dst_port), 
		&(rules[rules_size].ack),
		&(rules[rules_size].action),
		&(rules[rules_size].src_prefix_mask),
		&(rules[rules_size].dst_prefix_mask))){
		//(rules[rules_size].rule_name)[20] = '\0';
		rules_size++;
	printk("loaded rules: %s\n", buf);
	}
	return count;
}

ssize_t display_show_rules(struct device *dev, struct device_attribute *attr, char *buf){
	//create one long string for all rules
	char rules_str[12800];
	int i;
	rules_str[0] = '\0';
	char direction_str[2], src_ip_str[11], dst_ip_str[11], src_prefix_size_str[2];
	char dst_prefix_size_str[2], protocol_str[3], src_port_str[5], dst_port_str[5];
	char ack_str[2], action_str[2];
	//direction_str[0] = '\0';
	for (i = 0; i < rules_size; i++){
		strcat(rules_str, rules[i].rule_name);
		strcat(rules_str, " ");
		sprintf(direction_str, "%x", rules[i].direction);
		strcat(rules_str, direction_str);
		strcat(rules_str, " ");
		sprintf(src_ip_str, "%u", rules[i].src_ip);
		strcat(rules_str, src_ip_str);
		strcat(rules_str, "/");
		sprintf(src_prefix_size_str, "%hhu", rules[i].src_prefix_size);
		strcat(rules_str, src_prefix_size_str);
		strcat(rules_str, " ");
		sprintf(dst_ip_str, "%u", rules[i].dst_ip);
		strcat(rules_str, dst_ip_str);
		strcat(rules_str, "/");
		sprintf(dst_prefix_size_str, "%hhu", rules[i].dst_prefix_size);
		strcat(rules_str, dst_prefix_size_str);
		strcat(rules_str, " ");
		sprintf(protocol_str, "%hhu", rules[i].protocol);
		strcat(rules_str, protocol_str);
		strcat(rules_str, " ");
		sprintf(src_port_str, "%hu", rules[i].src_port);
		strcat(rules_str, src_port_str);
		strcat(rules_str, " ");
		sprintf(dst_port_str, "%hu", rules[i].dst_port);
		strcat(rules_str, dst_port_str);
		strcat(rules_str, " ");
		sprintf(ack_str, "%x", rules[i].ack);
		strcat(rules_str, ack_str);
		strcat(rules_str, " ");
		sprintf(action_str, "%x", rules[i].action);
		strcat(rules_str, action_str);
		strcat(rules_str, "\n");
	}//we don't need the prefix masks for the show_rules printing
	return scnprintf(buf, PAGE_SIZE, "%s", rules_str);
}

