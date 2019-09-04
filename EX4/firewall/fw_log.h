#ifndef FW_LOG_H_
#define FW_LOG_H_
#include "fw.h"

static log_row_t* logs = NULL;
static char* logs_str;

void clear_log(void);

unsigned int ip_str_to_hl_2(char* ip_str);

//compares a single log row to another - 
//returns 0 for similar and 1 for different
int compare_single_log_row(int ind, unsigned char protocol, unsigned char action, unsigned char hooknum, __be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, reason_t reason);

int add_new_log_row(unsigned long timestamp, unsigned char protocol, unsigned char action, unsigned char hooknum, __be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, reason_t reason);

//go over the log rows
//if there is a log row that fits the passed values - 
//count++ and update it with the new timestamp
//otherwise - add a new one
int add_to_logs(unsigned long timestamp, unsigned char protocol, unsigned char action, unsigned char hooknum, __be32 src_ip,  __be32 dst_ip, __be16 src_port, __be16 dst_port, reason_t reason);

void create_log_str(void);

int my_open_for_show_logs(struct inode *_inode, struct file *_file);

ssize_t my_read_for_show_logs(struct file *filp, char *buff, size_t length, loff_t *off);

ssize_t display_log_size(struct device *dev, struct device_attribute *attr, char *buf);

ssize_t modify_log_clear(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);




#endif /*FW_LOG_H_*/
