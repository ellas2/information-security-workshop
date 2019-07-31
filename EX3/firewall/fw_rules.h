#ifndef FW_RULES_H_
#define FW_RULES_H_
#include "fw.h"

static rule_t rules[MAX_RULES];


unsigned int prefix_size_to_mask(unsigned char prefix_size);

unsigned int ip_str_to_hl(char* ip_str);

void make_localhost_rule(void);

int num_rules(void);

int is_fw_active(void);

//check the two input IP addresses, see if they match, only the first few bits (masked bits) are compared
int check_ip(unsigned int ip, unsigned int ip_rule, unsigned int mask);

//a function to compare to rule at index ind
//if there is no match - returns 1
//if there is a match - returns 0
int compare_to_rule(int ind, direction_t direction, unsigned long src_ip, unsigned long dst_ip,
	prot_t protocol, ack_t ack, unsigned short src_port, unsigned short dst_port);

ssize_t display_rules_size(struct device *dev, struct device_attribute *attr, char *buf);

ssize_t display_active(struct device *dev, struct device_attribute *attr, char *buf);

ssize_t modify_active(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);

ssize_t modify_clear_rules(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);

ssize_t modify_load_rules(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);

ssize_t display_show_rules(struct device *dev, struct device_attribute *attr, char *buf);












#endif /*FW_RULES_H_*/





