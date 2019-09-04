#include <linux/string.h>
#include <linux/skbuff.h>
#include <linux/types.h>
#include <linux/ctype.h>
#include "fw_con_table.h"


static struct device *sysfs_device = NULL;

static DEVICE_ATTR(conn_table_size, S_IROTH , display_conn_table_size, NULL);
static DEVICE_ATTR(conns, S_IWOTH , NULL, modify_connection);
static DEVICE_ATTR(proxy, S_IRWXO , display_to_proxy, modify_from_proxy);
static DEVICE_ATTR(show_conn_table, S_IROTH, display_show_connections, NULL);


static __be32 src_ip_from_proxy;
static __be16 src_port_from_proxy;
static unsigned int con_table_size = 0;

static char* conn_str_buffer_ind;
static int conn_table_str_len;
	
const char* get_state_name(connection_state_t state){
	switch (state){
		case SYN_SENT: return "syn_sent";
		case CLOSED: return "closed";
		case EXPECTED_FTP: return "expected_ftp";
		case SYN_ACK_RECEIVED: return "syn_ack_received";
		case ESTABLISHED: return "established";
		case FIN_WAIT_ACK: return "fin_wait_ack";
		case FIN_WAIT_ACK_2: return "fin_wait_ack_2";
		case FIN_ACK_RECEIVED: return "fin_ack_received";
		default: return NULL;
	}
}

int num_tcp_connections(void){
	return con_table_size;
}


ssize_t display_conn_table_size(struct device *dev, struct device_attribute *attr, char *buf){
	return scnprintf(buf, PAGE_SIZE, "%u\n", num_tcp_connections());
}


ssize_t display_show_connections(struct device *dev, struct device_attribute *attr, char *buf){
	//create one long string for all the rules
	char src_ip_str[11], dst_ip_str[11], src_port_str[6], dst_port_str[6];
	char timestamp_str[10];
	int i;
	src_port_str[0] = '\0';
	dst_ip_str[0] = '\0';
	src_ip_str[0] = '\0';
	dst_port_str[0] = '\0';
	conn_table_str = NULL;
	conn_table_str = (char*)kmalloc(80*num_tcp_connections(), GFP_ATOMIC);
	conn_table_str[0] = '\0';
	for (i = 0; i < num_tcp_connections(); i++){
		sprintf(src_ip_str, "%u", conn_table[i].src_ip);
		strcat(conn_table_str, src_ip_str);
		strcat(conn_table_str, " ");
		sprintf(src_port_str, "%hu", conn_table[i].src_port);
		strcat(conn_table_str, src_port_str);
		strcat(conn_table_str, " ");
		sprintf(dst_ip_str, "%u", conn_table[i].dst_ip);
		strcat(conn_table_str, dst_ip_str);
		strcat(conn_table_str, " ");
		sprintf(dst_port_str, "%hu", conn_table[i].dst_port);
		strcat(conn_table_str, dst_port_str);
		strcat(conn_table_str, " ");
		if ((conn_table[i].dst_port == 80) || (conn_table[i].src_port == 80)){
			strcat(conn_table_str, "http");
		} else if ((conn_table[i].dst_port == 21) || (conn_table[i].src_port == 21) 
			|| (conn_table[i].dst_port == 20) || (conn_table[i].src_port == 20)){
			strcat(conn_table_str, "ftp");
		} else {
			strcat(conn_table_str, "tcp");
		}
		strcat(conn_table_str, " ");
		//state string
		strcat(conn_table_str, get_state_name(conn_table[i].conn_state));
		strcat(conn_table_str, " ");
		//timestamp
		sprintf(timestamp_str, "%lu", conn_table[i].timestamp);
		strcat(conn_table_str, timestamp_str);
		strcat(conn_table_str, "\n");
	}
	return scnprintf(buf, PAGE_SIZE, "%s", conn_table_str);
}

int add_new_conn_row(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, 
						connection_state_t conn_state, int rule_num){
	//if con_table is empty we need to allocate the memory
	struct timespec my_time;
	getnstimeofday(&my_time);
	if (con_table_size == 0){
		conn_table = (connection_t*)kmalloc(sizeof(connection_t), GFP_ATOMIC);
		if (conn_table == NULL){
			return -ENOMEM;
		}
	//if conn_table already exists we need to reallocate the memory
	} else{
		connection_t* new_conn_table = krealloc(conn_table,(con_table_size+1)*sizeof(connection_t), GFP_ATOMIC);
		if (new_conn_table == NULL){
			kfree(conn_table);
			return -ENOMEM;
		}
		conn_table = new_conn_table;
	}
	//conn_table[con_table_size].http_con = 0;
	conn_table[con_table_size].src_ip = src_ip;
	conn_table[con_table_size].dst_ip = dst_ip;
	conn_table[con_table_size].src_port = src_port;
	conn_table[con_table_size].dst_port = dst_port;
	conn_table[con_table_size].conn_state = conn_state;
	conn_table[con_table_size].timestamp = my_time.tv_sec;
	conn_table[con_table_size].rule_num = rule_num;
	printk("added connection row at %d with src_ip: %u, src_port: %hu, dst_ip: %u, dst_port: %hu\n", con_table_size, src_ip, src_port, dst_ip, dst_port);
	con_table_size++;
	return 0;
}


ssize_t display_to_proxy(struct device *dev, struct device_attribute *attr, char *buf){
	int i;
	char temp[FRAME_SIZE];
	char* buf_copy;
	int count;
	temp[0] = '\0';
	buf_copy = kmalloc(PAGE_SIZE, GFP_ATOMIC);
	if (buf_copy == NULL)
		return -1;
	for (i = 0; i < num_tcp_connections(); i++){
		if(conn_table[i].src_ip == src_ip_from_proxy
			&& conn_table[i].src_port == src_port_from_proxy
			&& conn_table[i].conn_state != CLOSED){
			sprintf(temp, "%d", conn_table[i].dst_ip);
			strcat(buf_copy, temp);
			strcat(buf_copy, " ");
			temp[0] = '\0';
			sprintf(temp, "%d", conn_table[i].dst_port);
			strcat(buf_copy, temp);
			break;
		}
	}
	buf[0] = '\0';
	count = scnprintf(buf, PAGE_SIZE, "%s", buf_copy);
	kfree(buf_copy);
	return count;

}


ssize_t modify_from_proxy(struct device *dev, struct device_attribute *attr, const char *buf, size_t count){
	//we write the values to our global variables
	int size = 0;
	int i, rule_num = 0;
	unsigned int src_ip, dst_ip;
	unsigned short src_port, dst_port;
	char *buf_copy, *token;
	buf_copy = kmalloc(PAGE_SIZE, GFP_ATOMIC);
	if (buf_copy == NULL){
		kfree(buf_copy);
		return -1;
	}
	if (count < PAGE_SIZE-1){
		size = count;
	} else {
		size = PAGE_SIZE-1;
	} 
	snprintf(buf_copy, PAGE_SIZE, "%.*s", size, buf);
	token = strsep(&buf_copy, " ");//get first "word"
	//we are working with the ftp case
	if (strcmp(token, "B") == 0){
		sscanf(buf, "%u %hu %u %hu", &src_ip, &src_port, &dst_ip, &dst_port);
		printk("got the following info from proxy:\n");
		printk("src ip: %u, src port: %hu, dst_ip: %u, dst_port: %hu\n", 
			src_ip, src_port, dst_ip, dst_port);
		for (i = 0; i < num_tcp_connections(); i++){
			if ((conn_table[i].src_ip == src_ip) && (conn_table[i].src_port == 21)){
				rule_num = conn_table[i].rule_num;
			}
		}
		if (add_new_conn_row(src_ip, dst_ip, src_port, dst_port, 
						EXPECTED_FTP, rule_num) == -1)
			printk("failed to add to connection table\n");
		if (add_new_conn_row(dst_ip, src_ip, dst_port, src_port,  
						EXPECTED_FTP, rule_num) == -1)
			printk("failed to add to connection table\n");
	}
	else{
		sscanf(buf, "%u %hu", &src_ip_from_proxy, &src_port_from_proxy);
		printk("got the following info from proxy:\n");
		printk("src ip: %u, src port: %hu\n", src_ip_from_proxy, src_port_from_proxy);
	}	
	kfree(buf_copy);
	return count;
}



ssize_t modify_connection(struct device *dev, struct device_attribute *attr, const char *buf, size_t count){
	unsigned int ip, i;
	struct timespec my_time;
	unsigned short port;
	if (sscanf(buf, "%u %hu", &ip, &port)){
		printk("got the following info from proxy:\n");
		printk("ip: %u, port: %hu\n", ip, port);
	}	
	getnstimeofday(&my_time);
	for (i = 0; i < num_tcp_connections(); i++){
		if((conn_table[i].src_ip == ip) && (conn_table[i].src_port == port)){
			if (add_to_logs(my_time.tv_sec, '6', NF_DROP, NF_INET_PRE_ROUTING, ip, 
							conn_table[i].dst_ip, conn_table[i].src_port, conn_table[i].dst_port, REASON_ILLEGAL_VALUE) == -1)
				printk("unable to add to logs\n");	
		}
		if ((conn_table[i].dst_ip == ip) && (conn_table[i].dst_port == port))	
			conn_table[i].conn_state = CLOSED;
		if ((port == 20) && (conn_table[i].src_ip == ip) && (conn_table[i].src_port == 21)){
			conn_table[i].conn_state = CLOSED;
			if (add_to_logs(my_time.tv_sec, '6', NF_DROP, NF_INET_PRE_ROUTING, ip, 
							conn_table[i].dst_ip, conn_table[i].src_port, conn_table[i].dst_port, REASON_ILLEGAL_VALUE) == -1)
				printk("unable to add to logs\n");	
		}
		if ((port == 20) && (conn_table[i].dst_ip == ip) && (conn_table[i].dst_port == 21))
			conn_table[i].conn_state = CLOSED;
	}	

	return count;
}



void remove_conn_row(int index){
	int i;
	for (i = index + 1; i < num_tcp_connections(); i++){
		conn_table[i-1].src_ip = conn_table[i].src_ip;
	conn_table[i-1].dst_ip = conn_table[i].dst_ip;
	conn_table[i-1].src_port = conn_table[i].src_port;
	conn_table[i-1].dst_port = conn_table[i].dst_port;
	conn_table[i-1].conn_state = conn_table[i].conn_state;
	conn_table[i-1].timestamp = conn_table[i].timestamp;
	conn_table[i-1].rule_num = conn_table[i].rule_num;
	}
	
	con_table_size--;
}


int find_my_match(int ind, __be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port){
	int i;
	for (i = 0; i < num_tcp_connections(); i++){
		if ((conn_table[ind].src_ip == conn_table[i].dst_ip) && (conn_table[ind].dst_ip == conn_table[i].src_ip)
			&& (conn_table[ind].src_port == conn_table[i]. dst_port) && (conn_table[ind].dst_port == conn_table[i]. src_port)
			&& (ind != i)){
			//printk("match for %d is %d\n", ind, i);
			return i;
		}
	}
	return -1;
}


void check_packet_with_con_table(prot_t protocol, unsigned int *is_existing_con, unsigned int src_ip, 
									unsigned int dst_ip, unsigned short src_port, 
									unsigned short dst_port, unsigned short ack, 
									unsigned short syn, unsigned short fin, unsigned short rst){
	struct timespec my_time;
	int existent;
	getnstimeofday(&my_time);
	int i;
	for (i = 0; i < num_tcp_connections(); i ++){
		if (!(((conn_table[i].src_ip == dst_ip) && (conn_table[i].dst_ip == src_ip)
			&& (conn_table[i].src_port == dst_port) && (conn_table[i].dst_port == src_port))) &&
			(((conn_table[i].src_ip == src_ip) && (conn_table[i].dst_ip == dst_ip)
			&& (conn_table[i].src_port == src_port) && (conn_table[i].dst_port == dst_port)))
			 && conn_table[i].conn_state == CLOSED){
			printk("removing closed connection from table\n");
			remove_conn_row(i);
			continue;
		}
		if (((conn_table[i].src_ip == src_ip) && (conn_table[i].dst_ip == dst_ip)
			&& (conn_table[i].src_port == src_port) && (conn_table[i].dst_port == dst_port)) ||
			(dst_port != 80 && dst_port != 21 && dst_port != 20 && dst_port != 25 && src_port != 80 && src_port != 21 
				&& src_port != 20 && src_port != 25) && (((conn_table[i].src_ip == dst_ip) && (conn_table[i].dst_ip == src_ip)
			&& (conn_table[i].src_port == dst_port) && (conn_table[i].dst_port == src_port)))) {
			//printk("in check_packet_with_con_table with:\n src_ip: %d, src_port: %d, dst_ip: %d, dst_port: %d, ack: %d, syn: %d, fin: %d, rst: %d\n",
			//src_ip, src_port, dst_ip, dst_port, ack, syn, fin, rst);
			//rst
			if (rst == 1){
				printk("rst is 1\n");
				conn_table[i].conn_state = CLOSED;
				conn_table[i].timestamp = my_time.tv_sec;
				is_existing_con[0] = NF_ACCEPT;
				is_existing_con[1] = conn_table[i].rule_num;
				existent = 1;
				printk("new state of line %d is - CLOSED\n", i);
			}
			//ftp data syn
			if ((conn_table[i].conn_state == EXPECTED_FTP) && (syn == 1) && (fin != 1)){
				printk("connection state is EXPECTED_FTP, syn is 1 and fin is 0\n");
				conn_table[i].timestamp = my_time.tv_sec;
				conn_table[i].conn_state = SYN_SENT;
				is_existing_con[0] = NF_ACCEPT;
				is_existing_con[1] = conn_table[i].rule_num;
				existent = 1;
				printk("new state of line %d is - SYN_SENT\n", i);
			} else if ((conn_table[i].conn_state == SYN_SENT) && (syn == 1) && (fin != 1)){
				printk("connection state is SYN_SENT, syn is 1 and fin is 0\n");
				conn_table[i].timestamp = my_time.tv_sec;
				conn_table[i].conn_state = SYN_ACK_RECEIVED;
				is_existing_con[0] = NF_ACCEPT;
				is_existing_con[1] = conn_table[i].rule_num;
				existent = 1;
				printk("new state of line %d is - SYN_ACK_RECEIVED\n", i);

			} else if ((conn_table[i].conn_state == SYN_ACK_RECEIVED) && (syn != 1) && (fin != 1)){
				printk("connection state is SYN_ACK_RECEIVED, syn is 0 and fin is 0\n");
				conn_table[i].timestamp = my_time.tv_sec;
				conn_table[i].conn_state = ESTABLISHED;
				is_existing_con[0] = NF_ACCEPT;
				is_existing_con[1] = conn_table[i].rule_num;
				existent = 1;
				printk("new state of line %d is - ESTABLISHED\n", i);
			} else if ((conn_table[i].conn_state == ESTABLISHED) && (syn != 1) && (fin == 1)){
				printk("connection state is ESTABLISHED, syn is 0 and fin is 1\n");
				conn_table[i].timestamp = my_time.tv_sec;
				conn_table[i].conn_state = FIN_WAIT_ACK;
				is_existing_con[0] = NF_ACCEPT;
				is_existing_con[1] = conn_table[i].rule_num;
				existent = 1;
				printk("new state of line %d and - FIN_WAIT_ACK\n", i);
			} else if ((conn_table[i].conn_state == FIN_WAIT_ACK || conn_table[i].conn_state == FIN_WAIT_ACK_2) && (syn != 1) && (fin == 1)){
				printk("connection state is FIN_WAIT_ACK or FIN_WAIT_ACK_2, syn is 0 and fin is 1\n");
				conn_table[i].timestamp = my_time.tv_sec;
				conn_table[i].conn_state = FIN_ACK_RECEIVED;
				is_existing_con[0] = NF_ACCEPT;
				is_existing_con[1] = conn_table[i].rule_num;
				existent = 1;
				printk("new state of line %d is - FIN_ACK_RECEIVED\n", i);
			} else if ((conn_table[i].conn_state == FIN_WAIT_ACK) && (syn != 1) && (fin != 1)){
				printk("connection state is FIN_WAIT_ACK, syn is 0 and fin is 0\n");
				conn_table[i].timestamp = my_time.tv_sec;
				conn_table[i].conn_state = FIN_WAIT_ACK_2;
				is_existing_con[0] = NF_ACCEPT;
				is_existing_con[1] = conn_table[i].rule_num;
				existent = 1;
				printk("new state of line %d - FIN_WAIT_ACK_2\n", i);

			} else if ((conn_table[i].conn_state == FIN_ACK_RECEIVED) && (syn != 1) && (fin != 1)){
				printk("connection state is FIN_ACK_RECEIVED, syn is 0 and fin is 0\n");
				conn_table[i].timestamp = my_time.tv_sec;
				conn_table[i].conn_state = CLOSED;
				is_existing_con[0] = NF_ACCEPT;
				is_existing_con[1] = conn_table[i].rule_num;
				existent = 1;
				printk("new state of line %d is - CLOSED\n", i);
			}
			//part of an open connection
			else if ((conn_table[i].conn_state == ESTABLISHED) && (syn != 1) && (fin != 1)){
				printk("connection state is ESTABLISHED, syn is 0 and fin is 0\n");
				conn_table[i].timestamp = my_time.tv_sec;
				//state need not be updated
				is_existing_con[0] = NF_ACCEPT;
				is_existing_con[1] = conn_table[i].rule_num;
				is_existing_con[2] = 1;
				existent = 1;
				printk("part of an open connection\n");
			}
		}

	}
	if (!existent){
		printk("unknowkn connection :O\n");
		is_existing_con[0] = NF_DROP;
		is_existing_con[1] = conn_table[i].rule_num;
		is_existing_con[2] = -1; 
	}


}


void update_proxy_port(unsigned int ip, unsigned short port, unsigned short proxy_port){

int i;
for (i = 0; i < num_tcp_connections(); i++){
	if ((conn_table[i].src_ip == ip) && (conn_table[i].src_port == port) 
		&& (conn_table[i].conn_state != CLOSED)){
			conn_table[i].proxy_port = proxy_port;
			printk("proxy port of line %d with src ip: %u and dst_ip: %u is being updated to: %hu\n", 
				i, conn_table[i].src_ip, conn_table[i].dst_ip, proxy_port);

	}
}


}

unsigned int get_actual_ip(unsigned int ip, unsigned short port, int src){
	int i;
	if (src < 0 || src > 1){
		return 0;
	} else if (src == 1){
			for (i = 0; i < num_tcp_connections(); i++){
				if ((conn_table[i].dst_ip == ip) && (conn_table[i].dst_port == port)){
						return conn_table[i].src_ip;
				}
			}
	}else {//dst
			for (i = 0; i < num_tcp_connections(); i++){
				if ((conn_table[i].src_ip == ip) && (conn_table[i].src_port == port)){
						return conn_table[i].dst_ip;
				}
			}

	}
	return 0;
}


unsigned short get_actual_port(unsigned int ip, unsigned short port, int src){
	int i;
	if (src < 0 || src > 1){
		return 0;
	} else if (src == 1){
			for (i = 0; i < num_tcp_connections(); i++){
				if ((conn_table[i].dst_ip == ip) && (conn_table[i].dst_port == port)){
						return conn_table[i].src_port;
				}
			}
	}else {//dst
			for (i = 0; i < num_tcp_connections(); i++){
				if ((conn_table[i].src_ip == ip) && (conn_table[i].src_port == port)){
						return conn_table[i].dst_port;
				}
			}

	}
	return 0;
}


unsigned short get_proxy_port(unsigned int ip, unsigned short port){
	int i;
	for (i = 0; i < num_tcp_connections(); i++){
		if ((conn_table[i].src_ip == ip) && (conn_table[i].src_port == port) 
			&& (conn_table[i].conn_state != CLOSED)){
				return conn_table[i].proxy_port;
		}
	}
	return 0;
}

int init_con_table_devices(struct class *sysfs_class, int major){
	//setting up the sysfs for sending the ips and ports
	//create sysfs device
	sysfs_device = device_create(sysfs_class, NULL, MKDEV(major, 2), NULL, "conn" "_" "tab");	
	if (IS_ERR(sysfs_device)){
		class_destroy(sysfs_class);
		unregister_chrdev(major, "fw_log");
		return -1;
	}
	//create sysfs file attributes	
	if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_proxy.attr)){
		device_destroy(sysfs_class, MKDEV(major, 2));
		class_destroy(sysfs_class);
		unregister_chrdev(major, "fw_log");
		return -1;
	}
	//create sysfs file attributes	
	if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_conns.attr)){
		device_destroy(sysfs_class, MKDEV(major, 2));
		class_destroy(sysfs_class);
		unregister_chrdev(major, "fw_log");
		return -1;
	}
	//create sysfs file attributes	
	if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_conn_table_size.attr)){
		device_destroy(sysfs_class, MKDEV(major, 2));
		class_destroy(sysfs_class);
		unregister_chrdev(major, "fw_log");
		return -1;
	}
	
	//create sysfs file attributes	
	if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_show_conn_table.attr)){
		device_destroy(sysfs_class, MKDEV(major, 2));
		class_destroy(sysfs_class);
		unregister_chrdev(major, "fw_log");
		return -1;
	}
	return 0;
}


void cleanup_con_table_devices(struct class *sysfs_class, int major){
	device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_conn_table_size.attr);
	device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_conns.attr);
	device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_proxy.attr);
	device_destroy(sysfs_class, MKDEV(major, 0));
	unregister_chrdev(major, "fw_log");
}
	