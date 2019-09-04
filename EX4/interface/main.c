#define _GNU_SOURCE
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include "auxil.h"
#include <errno.h>

#define RULES_DEVICE_PATH "/sys/class/fw/fw_rules"
#define LOG_DEVIDE_PATH "/sys/class/fw/fw_log"
#define CONN_TABLE_DEVICE_PATH "/sys/class/fw/conn_tab"


int activate(){
	int fd;
	fd = open(RULES_DEVICE_PATH "/active", O_WRONLY);
	if (fd < 0){
		printf("Cannot open active sysfs\n");
		return -1;
	}
	//Writing 1 to "active" sysfs should activate the fw
	if (write(fd, "1", 4) == -1){
		printf("Error while writing to active sysfs device file\n");
		close(fd);
		return -1;	
	}
	close(fd);
	return 0;
}

int deactivate(){
	int fd;
	if ((fd = open(RULES_DEVICE_PATH "/active", O_WRONLY)) < 0){
		printf("Cannot open active sysfs\n");
		return -1;
	}
	//Writing 0 to "active" sysfs should deactivate the fw
	if (write(fd, "0", 4) == -1){
		printf("Error while writing to active sysfs device file\n");
		close(fd);
		return -1;	
	}
	close(fd);
	return 0;
}


int show_conn_tab(){
	time_t now;
	struct tm ts;
	char time_buf[80];
	char* token;
	char* conn_table = NULL;
	int bytes_to_read, fd, fd_buf_size, first;
	char buf_size[11];
	char curr_parsed_conn[80];
	char src_port_str[6], dst_port_str[6];
	char timestamp_str[10];
	unsigned int src_ip_int, dst_ip_int;
	char src_ip_bytes[4], dst_ip_bytes[4], src_ip_str[7], dst_ip_str[7];
	unsigned int timestamp;
	fd = -1;
	//calculate buffer size - we read the number of connection in the table 
	//and then allocate the log buffer accordingly
	if ((fd_buf_size = open(CONN_TABLE_DEVICE_PATH "/conn_table_size", O_RDONLY)) < 0){
		printf("Cannot open conn_tab sysfs device file\n");
		return -1;
	}
	if ((read(fd_buf_size, buf_size, 11)) == -1){
		printf("Error while reading from conn_tab sysfs device file\n");
		close(fd);
		return -1;	
	}
	bytes_to_read = atoi(buf_size)*80;//num_connections*connection_str_size
	if (bytes_to_read == 0){
		printf("Connection table is empty\n");
		return 0;
	}
	conn_table = (char*)malloc(bytes_to_read);
	curr_parsed_conn[0] = '\0';
	if ((fd = open(CONN_TABLE_DEVICE_PATH "/show_conn_table", O_RDONLY)) < 0){//TODO:there might be a problem with the path
		printf("Cannot open conn_table device file for reading\n");
		return -1;
	}
	if ((read(fd, conn_table, bytes_to_read)) == -1){
		printf("Error while reading from conn_table device file\n");
		close(fd);
		return -1;	
	}
	first = 1;
	printf("src_ip src_port dst_ip  dst_port protocol state timestamp\n");
	token = strtok(conn_table, " ");//get first src_ip
	while (1){
		if(!first){
			token = strtok(NULL, " ");
			if (!token){//end of connection table
				break;
			}
		}
		first = 0;
		//src_ip
		src_ip_int = atoi(token);
		src_ip_bytes[0] = src_ip_int & 0xFF;
		src_ip_bytes[1] = (src_ip_int >> 8) & 0xFF;
		src_ip_bytes[2] = (src_ip_int >> 16) & 0xFF;
		src_ip_bytes[3] = (src_ip_int >> 24) & 0xFF;
		sprintf(src_ip_str, "%hhu.%hhu.%hhu.%hhu", 
			(src_ip_bytes[0]), (src_ip_bytes[1]), (src_ip_bytes[2]), (src_ip_bytes[3]));
		strcat(curr_parsed_conn, src_ip_str);//1.2.3.4
		strcat(curr_parsed_conn, " ");//_
		//src_port
		if ((token = strtok(NULL, " ")) == NULL)//token in middle of log line is empty
			return -1;
		strcat(curr_parsed_conn, token);//src_port
		strcat(curr_parsed_conn, " ");//_
		//dst_ip
		if ((token = strtok(NULL, " ")) == NULL)//token in middle of log line is empty
			return -1;
		dst_ip_int = atoi(token);
		dst_ip_bytes[0] = dst_ip_int & 0xFF;
		dst_ip_bytes[1] = (dst_ip_int >> 8) & 0xFF;
		dst_ip_bytes[2] = (dst_ip_int >> 16) & 0xFF;
		dst_ip_bytes[3] = (dst_ip_int >> 24) & 0xFF;
		sprintf(dst_ip_str, "%hhu.%hhu.%hhu.%hhu", 
			(dst_ip_bytes[0]), (dst_ip_bytes[1]), (dst_ip_bytes[2]), (dst_ip_bytes[3]));
		strcat(curr_parsed_conn, dst_ip_str);//1.2.3.4
		strcat(curr_parsed_conn, " ");//_
		//dst_port
		if ((token = strtok(NULL, " ")) == NULL)//token in middle of log line is empty
			return -1;
		strcat(curr_parsed_conn, token);//dst_port
		strcat(curr_parsed_conn, " ");//_
		//protocol
		if ((token = strtok(NULL, " ")) == NULL)//token in middle of log line is empty
			return -1;
		strcat(curr_parsed_conn, token);//protocol
		strcat(curr_parsed_conn, " ");//_
		//state
		if ((token = strtok(NULL, " ")) == NULL)//token in middle of log line is empty
			return -1;
		strcat(curr_parsed_conn, token);//state
		strcat(curr_parsed_conn, " ");//_
		//timestamp
		if ((token = strtok(NULL, " ")) == NULL)//token in middle of log line is empty
			return -1;
		timestamp = atoi(token);
		now = (time_t)timestamp;
		ts = *localtime(&now);
		strftime(time_buf, sizeof(time_buf), "%d/%m/%Y %H:%M:%S", &ts);
		strcat(curr_parsed_conn, time_buf);//timestamp
		strcat(curr_parsed_conn, "\n");//_
		printf("%s", curr_parsed_conn);
		curr_parsed_conn[0] = '\0';
	}
	free(token);
	free(conn_table);
	close(fd);
	close(fd_buf_size);
	return 0;
}

int show_log(){
	time_t now;
	struct tm ts;
	char time_buf[80];
	char* token;
	char* log = NULL;
	int bytes_to_read, fd, fd_buf_size, first;
	char buf_size[11];
	char curr_parsed_log[70];
	char reason_int_buf[2];
	char protocol_str[4], action_str[6], reason_str_2[11];
	unsigned int src_ip_int, dst_ip_int;
	int reason_int;
	char src_ip_bytes[4], dst_ip_bytes[4], src_ip_str[7], dst_ip_str[7];
	unsigned int timestamp;
	fd = -1;
	//calculate buffer size - we read the number of logs 
	//and then allocate the log buffer accordingly
	if ((fd_buf_size = open(LOG_DEVIDE_PATH "/log_size", O_RDONLY)) < 0){
		printf("Cannot open log_size sysfs device file\n");
		return -1;
	}
	if ((read(fd_buf_size, buf_size, 11)) == -1){
		printf("Error while reading from show_rules sysfs device file\n");
		close(fd);
		return -1;	
	}
	bytes_to_read = atoi(buf_size)*70;//num_logs*log_size
	if (bytes_to_read == 0){
		printf("Logs are empty\n");
		return 0;
	}
	int errnum;
	log = (char*)malloc(bytes_to_read);
	curr_parsed_log[0] = '\0';
	if ((fd = open("/dev/fw_log", O_RDONLY)) < 0){
		printf("Cannot open /dev/fw_log device file for reading\n");
		return -1;
	}
	if ((read(fd, log, bytes_to_read)) == -1){
		printf("Error while reading from log device file\n");
		close(fd);
		return -1;	
	}
	first = 1;
	printf("timestamp src_ip dst_ip src_port dst_port protocol hooknum action reason count\n");
	token = strtok(log, " ");//get first timestamp
	while (1){
		if(!first){
			token = strtok(NULL, " ");
			if (!token){//end of log
				break;
			}
		}
		first = 0;
		timestamp = atoi(token);
		now = (time_t)timestamp;
		ts = *localtime(&now);
		
		strftime(time_buf, sizeof(time_buf), "%d/%m/%Y %H:%M:%S", &ts);
		strcat(curr_parsed_log, time_buf);//timestamp
		strcat(curr_parsed_log, " ");//_
		//protocol
		if ((token = strtok(NULL, " ")) == NULL)//token in middle of log line is empty
			return -1;
		strcpy(protocol_str, protocol_int_to_str(atoi(token)));
		strcat(curr_parsed_log, protocol_str);//protocol_str
		strcat(curr_parsed_log, " ");//_
		//action
		if ((token = strtok(NULL, " ")) == NULL)//token in middle of log line is empty
			return -1;
		strcpy(action_str, action_int_to_str(atoi(token)));
		strcat(curr_parsed_log, action_str);//action_str
		strcat(curr_parsed_log, " ");//_
		//hooknum
		if ((token = strtok(NULL, " "))== NULL)//token in middle of log line is empty
			return -1;
		strcat(curr_parsed_log, token);//hooknum
		strcat(curr_parsed_log, " ");//_
		//src_ip
		if ((token = strtok(NULL, " ")) == NULL)//token in middle of log line is empty
			return -1;
		src_ip_int = atoi(token);
		src_ip_bytes[0] = src_ip_int & 0xFF;
		src_ip_bytes[1] = (src_ip_int >> 8) & 0xFF;
		src_ip_bytes[2] = (src_ip_int >> 16) & 0xFF;
		src_ip_bytes[3] = (src_ip_int >> 24) & 0xFF;
		sprintf(src_ip_str, "%hhu.%hhu.%hhu.%hhu", 
			(src_ip_bytes[0]), (src_ip_bytes[1]), (src_ip_bytes[2]), (src_ip_bytes[3]));
		strcat(curr_parsed_log, src_ip_str);//1.2.3.4
		strcat(curr_parsed_log, " ");//_
		//dst_ip
		if ((token = strtok(NULL, " ")) == NULL)//token in middle of log line is empty
			return -1;
		dst_ip_int = atoi(token);
		dst_ip_bytes[0] = dst_ip_int & 0xFF;
		dst_ip_bytes[1] = (dst_ip_int >> 8) & 0xFF;
		dst_ip_bytes[2] = (dst_ip_int >> 16) & 0xFF;
		dst_ip_bytes[3] = (dst_ip_int >> 24) & 0xFF;
		sprintf(dst_ip_str, "%hhu.%hhu.%hhu.%hhu", 
			(dst_ip_bytes[0]), (dst_ip_bytes[1]), (dst_ip_bytes[2]), (dst_ip_bytes[3]));
		strcat(curr_parsed_log, dst_ip_str);//1.2.3.4
		strcat(curr_parsed_log, " ");//_
		//src_port
		if ((token = strtok(NULL, " ")) == NULL)//token in middle of log line is empty
			return -1;
		strcat(curr_parsed_log, token);//src_port
		strcat(curr_parsed_log, " ");//_
		//dst_port
		if ((token = strtok(NULL, " ")) == NULL)//token in middle of log line is empty
			return -1;
		strcat(curr_parsed_log, token);//dst_port
		strcat(curr_parsed_log, " ");//_
		//reason
		if ((token = strtok(NULL, " ")) == NULL)//token in middle of log line is empty
			return -1;
		reason_int = atoi(token);
		if (reason_int > 0){//reason_int is a rule line
			sprintf(reason_int_buf, "%d", reason_int);
			strcat(curr_parsed_log, reason_int_buf);
		} else{
			strcat(curr_parsed_log, reason_int_to_str(reason_int));//reason_str
		}
		strcat(curr_parsed_log, " ");//_
		//count
		if ((token = strtok(NULL, "\n")) == NULL)//token in middle of log line is empty
			return -1;
		strcat(curr_parsed_log, token);//count
		strcat(curr_parsed_log, "\n");//_
		printf("%s", curr_parsed_log);
		curr_parsed_log[0] = '\0';
	}
	free(token);
	free(log);
	close(fd);
	close(fd_buf_size);
	return 0;
}



int show_rules(){
	char* token; 
	char rules[12800];
	char curr_parsed_rule[300], rules_cpy[12800];	
	char direction_str[3], protocol_str[4], ack_str[3], action_str[6];
	int fd, first;
	unsigned int src_ip_int, dst_ip_int;
	char src_ip_bytes[4], dst_ip_bytes[4], src_ip_str[7], dst_ip_str[7];
	if ((fd = open(RULES_DEVICE_PATH "/show_rules", O_RDONLY)) < 0){
		printf("Cannot open show_rules sysfs\n");
		return -1;
	}
	//we read one rule at a time
	curr_parsed_rule[0] = '\0';
	if ((read(fd, rules, 12800)) == -1){//12800 is the max size for 50 rules
		printf("Error while reading from show_rules sysfs device file\n");
		close(fd);
		return -1;	
	}
	//printf("RULES: %s\n", rules);
	strcpy(rules_cpy,rules);
	first = 1;
	token = strtok(rules_cpy, " ");//get first rule_name
	while (1){
		//rule_name
		if (!first){
			token = strtok(NULL, " ");
			if (!token || strcmp(token, "\n") == 0){//end of rules
				break;
			}
		}
		first = 0;
		strcat(curr_parsed_rule, token);//rule_name
		strcat(curr_parsed_rule, " ");//_
		//direction - parse from int to string
		if ((token = strtok(NULL, " ")) == NULL)//token in middle of rule line is empty
			return -1;
		strcpy(direction_str, direction_int_to_str(atoi(token)));
		strcat(curr_parsed_rule, direction_str);//direction_str 
		strcat(curr_parsed_rule, " ");//_
		//src ip - parse from int to string
		if ((token = strtok(NULL, "/")) == NULL)//token in middle of rule line is empty
			return -1;
		src_ip_int = atoi(token);
		if (src_ip_int == 0){
			strcat(curr_parsed_rule, "any");
			if ((token = strtok(NULL, " ")) == NULL)//token in middle of rule line is empty
				return -1;
			strcat(curr_parsed_rule, " ");//_
		} else{
			src_ip_bytes[0] = src_ip_int & 0xFF;
			src_ip_bytes[1] = (src_ip_int >> 8) & 0xFF;
			src_ip_bytes[2] = (src_ip_int >> 16) & 0xFF;
			src_ip_bytes[3] = (src_ip_int >> 24) & 0xFF;
			sprintf(src_ip_str, "%hhu.%hhu.%hhu.%hhu", 
				(src_ip_bytes[3]), (src_ip_bytes[2]), (src_ip_bytes[1]), (src_ip_bytes[0]));
			strcat(curr_parsed_rule, src_ip_str);//1.2.3.4
			strcat(curr_parsed_rule, "/");///
			//nps
			if ((token = strtok(NULL, " ")) == NULL)//token in middle of rule line is empty
				return -1;
			strcat(curr_parsed_rule, token);//nps
			strcat(curr_parsed_rule, " ");//_
		}
		//dst ip - parse from int to string
		if ((token = strtok(NULL, "/")) == NULL)//token in middle of rule line is empty
			return -1;
		dst_ip_int = atoi(token);
		if (dst_ip_int == 0){
			strcat(curr_parsed_rule, "any");
			if ((token = strtok(NULL, " ")) == NULL)//token in middle of rule line is empty
				return -1;
			strcat(curr_parsed_rule, " ");//_
		} else{
			dst_ip_bytes[0] = dst_ip_int & 0xFF;
			dst_ip_bytes[1] = (dst_ip_int >> 8) & 0xFF;
			dst_ip_bytes[2] = (dst_ip_int >> 16) & 0xFF;
			dst_ip_bytes[3] = (dst_ip_int >> 24) & 0xFF;
			sprintf(dst_ip_str, "%hhu.%hhu.%hhu.%hhu", 
				(dst_ip_bytes[3]), (dst_ip_bytes[2]), (dst_ip_bytes[1]), (dst_ip_bytes[0]));
			strcat(curr_parsed_rule, dst_ip_str);//1.2.3.4
			strcat(curr_parsed_rule, "/");///
			//nps
			if ((token = strtok(NULL, " ")) == NULL)//token in middle of rule line is empty
				return -1;
			strcat(curr_parsed_rule, token);//nps
			strcat(curr_parsed_rule, " ");//_
		}
		//protocol
		if ((token = strtok(NULL, " ")) == NULL)//token in middle of rule line is empty
			return -1;
		strcpy(protocol_str, protocol_int_to_str(atoi(token)));
		strcat(curr_parsed_rule, protocol_str);//protocol_str
		strcat(curr_parsed_rule, " ");//_
		//src_port
		if ((token = strtok(NULL, " ")) == NULL)//token in middle of rule line is empty
			return -1;
		if (strcmp(token, "0") == 0)
			strcat(curr_parsed_rule, "any");
		else if (strcmp(token, "1023") == 0)
			strcat(curr_parsed_rule, ">1023");
		else
			strcat(curr_parsed_rule, token);//src_port
		strcat(curr_parsed_rule, " ");//_
		//dst_port
		if ((token = strtok(NULL, " ")) == NULL)//token in middle of rule line is empty
			return -1;
		if (strcmp(token, "0") == 0)
			strcat(curr_parsed_rule, "any");
		else if (strcmp(token, "1023") == 0)
			strcat(curr_parsed_rule, ">1023");
		else
			strcat(curr_parsed_rule, token);//dst_port
		strcat(curr_parsed_rule, " ");//_
		//ack -parse from int to string
		if ((token = strtok(NULL, " ")) == NULL)//token in middle of rule line is empty
			return -1;
		strcpy(ack_str, ack_int_to_str(atoi(token)));
		strcat(curr_parsed_rule, ack_str);//ack_str
		strcat(curr_parsed_rule, " ");//_
		//action
		if ((token = strtok(NULL, "\n")) == NULL)//token in middle of rule line is empty
			return -1;
		strcpy(action_str, action_int_to_str(atoi(token)));
		strcat(curr_parsed_rule, action_str);//action_str
		strcat(curr_parsed_rule, "\n");//_
		printf("%s", curr_parsed_rule);
		curr_parsed_rule[0] = '\0';
	}
	free(token);
	close(fd);
	return 0;
}

int load_rules(char* file_path){
	int i, j;
	char str_src_ip_nps[14], str_dst_ip_nps[14], src_nps_str[2], dst_nps_str[2];


	FILE* stream;
	ssize_t nread;
	size_t len;
	char src_ip_str[11], src_ip_str2[11], dst_ip_str[11], dst_ip_str2[11], curr_parsed_line[256], direction_int_str[3];
	char protocol_int_str[3], ack_str[2], action_str[2], src_mask_str[11], dst_mask_str[11];
	int fd, protocol_int, direction_int, ack_int, action_int;
	char* token;
	unsigned int src_ip, dst_ip, src_prefix_mask, dst_prefix_mask;
	unsigned int src_prefix_size_int, dst_prefix_size_int;
	char* curr_line;
	fd = 0;
	int src_prefix_mask_zero = 0;
	int dst_prefix_mask_zero = 0;

	if ((stream = fopen(file_path, "r")) == NULL){
		printf("Cannot open file path provided as second argument\n");
		return -1;
	}
	if ((fd = open(RULES_DEVICE_PATH "/load_rules", O_WRONLY)) < 0){
		printf("Cannot open load_rules sysfs\n");
		return -1;
	}
	len = 0;
	curr_line = NULL;
	curr_parsed_line[0] = '\0';
	len = 0;
	j=0;
	while((nread = getline(&curr_line, &len, stream)) != -1){
		if ((token = strtok(curr_line, " ")) == NULL)	
			return -1;
		strcat(curr_parsed_line, token);//rule_name
		strcat(curr_parsed_line, " ");
		if ((token = strtok(NULL, " ")) == NULL)
			return -1;
		direction_int = direction_str_to_int(token);
		if (direction_int == -1){
			return -1;
		}
		sprintf(direction_int_str, "%d", direction_int);
		strcat(curr_parsed_line, direction_int_str);//direction
		strcat(curr_parsed_line, " "); 
		if ((token = strtok(NULL, " ")) == NULL)//src_ip_str/nps or any
			return -1;
		if ((strcmp(token, "any") == 0) || (strcmp(token, "Any")) == 0){
			strcat(curr_parsed_line, "0/0");
			strcat(curr_parsed_line, " ");
			src_prefix_mask_zero = 1;
		} else{
			src_ip_str[0] = '\0';
			i = 0;
			strcpy(str_src_ip_nps, token);
			while (str_src_ip_nps[i]!= '/' && i < strlen(str_src_ip_nps)){
				src_ip_str[i] = str_src_ip_nps[i];
				i++;
			}
			src_ip_str[i] = '\0';
			src_ip = ip_str_to_hl(src_ip_str);
			if (src_ip > 4294967295)//max int for ip 
				return -1;
			i++;
			j=0;
			sprintf(src_ip_str2, "%u", src_ip);
			strcat(curr_parsed_line, src_ip_str2);//source_ip in int format 
			strcat(curr_parsed_line, "/");
			while(i < strlen(str_src_ip_nps)){
				src_nps_str[j] = str_src_ip_nps[i];
				i++;
				j++;
			}
			src_nps_str[j]='\0';
			src_prefix_size_int = atoi(src_nps_str);
			if (src_prefix_size_int > 32)
				return -1;
			strcat(curr_parsed_line, src_nps_str);//nps
			strcat(curr_parsed_line, " ");
		}
		if ((token = strtok(NULL, " ")) == NULL)//dst_ip_str/nps or any
			return -1;
		if ((strcmp(token, "any") == 0) || (strcmp(token, "Any")) == 0){
			strcat(curr_parsed_line, "0/0");
			strcat(curr_parsed_line, " ");
			dst_prefix_mask_zero = 1;
		} else{
			dst_ip_str[0] = '\0';
			i = 0;
			strcpy(str_dst_ip_nps, token);
			while (str_dst_ip_nps[i]!= '/' && i < strlen(str_dst_ip_nps)){
				dst_ip_str[i] = str_dst_ip_nps[i];
				i++;
			}
			dst_ip_str[i] = '\0';
			dst_ip = ip_str_to_hl(dst_ip_str);
			if (dst_ip > 4294967295)//max int for ip 
				return -1;
			i++;
			j=0;
			sprintf(dst_ip_str2, "%u", dst_ip);
			strcat(curr_parsed_line, dst_ip_str2);//source_ip in int format 
			strcat(curr_parsed_line, "/");
			while(i < strlen(str_dst_ip_nps)){
				dst_nps_str[j] = str_dst_ip_nps[i];
				i++;
				j++;
			}
			dst_nps_str[j]='\0';
			src_prefix_size_int = atoi(dst_nps_str);
			if (src_prefix_size_int > 32)
				return -1;
			strcat(curr_parsed_line, dst_nps_str);//nps
			strcat(curr_parsed_line, " ");
		}

		if ((token = strtok(NULL, " ")) == NULL)//token has the protocol
			return -1;
		protocol_int = protocol_str_to_int(token);
		if (protocol_int == -1){
			printf("Invalid protocol: Should be either ICMP, UDP, TCP or Any\n");
			return -1;
		}
		sprintf(protocol_int_str, "%d", protocol_int);
		strcat(curr_parsed_line, protocol_int_str);
		strcat(curr_parsed_line, " ");
		if ((token = strtok(NULL, " ")) == NULL)//src_port
			return -1;
		if ((strcmp(token, "any") == 0) || (strcmp(token, "Any")  == 0))
			strcat(curr_parsed_line, "0");
		else if ((strcmp(token, ">1023") == 0) || (strcmp(token, "> 1023") == 0))
			strcat(curr_parsed_line, "1023");
		else
			strcat(curr_parsed_line, token);
		strcat(curr_parsed_line, " ");  
		if((token = strtok(NULL, " ")) == NULL)//dst_port
			return -1;
		if ((strcmp(token, "any") == 0) || (strcmp(token, "Any")  == 0))
			strcat(curr_parsed_line, "0");
		else if ((strcmp(token, ">1023") == 0) || (strcmp(token, "> 1023") == 0))
			strcat(curr_parsed_line, "1023");
		else
			strcat(curr_parsed_line, token);
		strcat(curr_parsed_line, " "); 
		if ((token = strtok(NULL, " ")) == NULL)//ack
			return -1;
		ack_int = ack_str_to_int(token);
		if (ack_int == -1){
			printf("Invalid ack: Should be either Yes, No or Any\n");
			return -1;
		}
		sprintf(ack_str, "%d", ack_int);
		strcat(curr_parsed_line, ack_str);
		strcat(curr_parsed_line, " "); 
		if ((token = strtok(NULL, "\n")) == NULL)//action
			return -1;
		action_int = action_str_to_int(token);
		if (action_int == -1){
			printf("Invalid action: Should be either Drop or Accept\n");
			return -1;
		}
		sprintf(action_str, "%d", action_int);
		strcat(curr_parsed_line, action_str);
		strcat(curr_parsed_line, " ");
		if (src_prefix_mask_zero == 1)
			src_prefix_mask = 0;
		else
			src_prefix_mask = prefix_size_to_mask(src_prefix_size_int);
		sprintf(src_mask_str, "%u", src_prefix_mask);
		strcat(curr_parsed_line, src_mask_str);
		strcat(curr_parsed_line, " ");
		if (dst_prefix_mask_zero == 1)
			dst_prefix_mask = 0;
		else
			dst_prefix_mask = prefix_size_to_mask(dst_prefix_size_int);
		sprintf(dst_mask_str, "%u", dst_prefix_mask);
		strcat(curr_parsed_line, dst_mask_str);
		//write the parsed line to the sysfs device file
		if (write(fd, curr_parsed_line, strlen(curr_parsed_line)) == -1){
			printf("Error while writing to load_rules sysfs device file\n");
			close(fd);
			return -1;	
		}
		curr_parsed_line[0] = '\0';
		token = NULL;
		curr_line = NULL;
		len = 0;
		direction_int = 0;	
	}
	free(token);
	free(curr_line);
	fclose(stream);
	close(fd);
	return 0;
}

int clear_rules(){
	int fd;
	if ((fd = open(RULES_DEVICE_PATH "/clear_rules", O_WRONLY)) < 0){
		printf("Cannot open clear_rules sysfs\n");
		return -1;
	}
	//Writing 0 to "active" sysfs should deactivate the fw
	if (write(fd, "0", 4) == -1){
		printf("Error while writing to clear_rules sysfs device file\n");
		close(fd);
		return -1;	
	}
	close(fd);
	return 0;
}

int clear_log(){
	int fd;
	if ((fd = open(LOG_DEVIDE_PATH "/log_clear", O_WRONLY)) < 0){
		printf("Cannot open log_clear sysfs\n");
		return -1;
	}
	//Writing any char clears the logs
	if (write(fd, "0", 4) == -1){
		printf("Error while writing to log_clear sysfs device file\n");
		close(fd);
		return -1;	
	}
	close(fd);
	return 0;
}


int main(int argc, char** argv){
	if (argc > 3){
		printf("Invalid number of arguments\n");
		exit(-1);
	} else if (argc == 2){
		if (strcmp(argv[1], "activate") == 0){
			if (activate() == -1)
				exit (-1);
		} 
		else if (strcmp(argv[1], "deactivate") == 0){
			if (deactivate() == -1)
				exit(-1);
		} else if (strcmp(argv[1], "show_rules") == 0){
			if (show_rules() == -1)
				exit(-1);
		} else if (strcmp(argv[1], "clear_rules") == 0){
			if (clear_rules() == -1)
				exit(-1);
		} else if (strcmp(argv[1], "show_log") == 0){
			if (show_log() == -1)
				exit(-1);
		} else if (strcmp(argv[1], "clear_log") == 0){
			if (clear_log() == -1)
				exit(-1);
		} else if (strcmp(argv[1], "show_connection_table") == 0){ 
			if (show_conn_tab() == -1)
				exit(-1);
		}else{
			printf("Invalid input argumnets\n");
			exit(-1);
		}
	} 
	else if (strcmp(argv[1], "load_rules") == 0){
		//we have to first clear the rules
		if (clear_rules() == -1)
				exit(-1);
		if (load_rules(argv[2]) == -1)
				exit(-1);
	} else{
		printf("Invalid input argumnets\n");
		exit(-1);
	}
	
	exit(0);
}