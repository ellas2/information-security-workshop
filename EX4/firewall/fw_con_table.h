#ifndef FW_CON_TABLE_H_
#define FW_CON_TABLE_H_
#include <linux/time.h>
#include <linux/types.h>

#include "fw.h"
#include "fw_log.h"

typedef enum {
	SYN_SENT,
	SYN_ACK_RECEIVED,
	ESTABLISHED,
	CLOSED,
	FIN_WAIT_ACK, 
	FIN_WAIT_ACK_2,
	FIN_ACK_RECEIVED,
	EXPECTED_FTP
} connection_state_t;

typedef struct {
	__be32	src_ip;
	__be32	dst_ip;
	__be16	src_port; 			
	__be16	dst_port; 
	connection_state_t conn_state;	
	time_t timestamp; //for timeout	
	int rule_num;
	__be16 proxy_port;
} connection_t;

static char *conn_table_str;

static connection_t* conn_table = NULL;



int add_new_conn_row(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, connection_state_t conn_state, int rule_num);

int num_tcp_connections(void);

ssize_t display_to_proxy(struct device *dev, struct device_attribute *attr, char *buf);

ssize_t modify_from_proxy(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);

void check_packet_with_con_table(prot_t protocol, unsigned int *is_existing_con, unsigned int src_ip, 
									unsigned int dst_ip, unsigned short src_port, 
									unsigned short dst_port, unsigned short ack, 
									unsigned short syn, unsigned short fin, unsigned short rst);

unsigned short get_proxy_port(unsigned int ip, unsigned short port);

unsigned int get_actual_ip(unsigned int ip, unsigned short port, int src);

unsigned short get_actual_port(unsigned int ip, unsigned short port, int src);

void update_proxy_port(unsigned int ip, unsigned short port, unsigned short proxy_port);

ssize_t display_conn_table_size(struct device *dev, struct device_attribute *attr, char *buf);

ssize_t modify_connection(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);

int init_con_table_devices(struct class *sysfs_class, int major);

void cleanup_con_table_devices(struct class *sysfs_class, int major);

int find_my_match(int ind, __be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port);

int set_conn_state(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port);

ssize_t display_show_connections(struct device *dev, struct device_attribute *attr, char *buf);


#endif /*FW_CON_TABLE_H_*/
