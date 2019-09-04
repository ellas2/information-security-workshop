#define _GNU_SOURCE
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include "auxil.h"

#define RULES_DEVICE_PATH "/sys/class/fw/fw_rules"
#define LOG_DEVIDE_PATH "/sys/class/fw/fw_log" 



char* reason_int_to_str(int reason_int){
	char* reason_str;
	//char reason_int_buf[2];
	reason_str = NULL;
	if (reason_int == -1){
		reason_str = "REASON_FW_INACTIVE";
	} else if(reason_int == -2){
		reason_str = "REASON_NO_MATCHING_RULE";
	} else if(reason_int == -4){
		reason_str ="REASON_XMAS_PACKET";
	} else if (reason_int == -6){
		reason_str = "REASON_ILLEGAL_VALUE";
	} 
	return reason_str;
}

char* protocol_int_to_str(int protocol_int){
	char* protocol_str;
	if (protocol_int == 6){ 
		protocol_str = "tcp";
	} else if (protocol_int == 1){
		protocol_str = "icmp";
	} else if(protocol_int == 17){
		protocol_str = "udp";
	} else if(protocol_int == 143){ 
		protocol_str = "any";
	} 
	return protocol_str;
}


char* direction_int_to_str(int direction_int){
	char* direction_str;
	if (direction_int == 0x01){
		direction_str = "in";
	} else if (direction_int == 0x02){
		direction_str = "out";
	} else if(direction_int == (0x01 | 0x02)){
		direction_str = "any";
	} 
	return direction_str;
}


char* ack_int_to_str(int ack_int){
	char* ack_str;
	if (ack_int == 0x02){
		ack_str = "yes";
	} else if (ack_int == 0x01){
		ack_str = "no";
	} else if(ack_int == (0x01 | 0x02)){
		ack_str = "any";
	} 
	return ack_str;
}

char* action_int_to_str(int action_int){
	char* action_str;
	if (action_int == 0){
		action_str = "drop";
	} else if (action_int == 1){
		action_str = "accept";
	} 
	return action_str;
}

unsigned int ip_str_to_hl(char* ip_str){
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
    return ip;
}

int protocol_str_to_int(char* protocol_str){
	if ((strcmp(protocol_str, "Any") == 0) || 
		(strcmp(protocol_str, "any") == 0) ){
		return 143;
	} else if ((strcmp(protocol_str, "TCP") == 0) || 
		(strcmp(protocol_str, "tcp") == 0)){
		return 6;
	} else if((strcmp(protocol_str, "UDP") == 0) || 
		(strcmp(protocol_str, "udp") == 0)){
		return 17;
	} else if((strcmp(protocol_str, "ICMP") == 0) || 
		(strcmp(protocol_str, "icmp") == 0)){
		return 1;
	} 
	return -1;
}

int direction_str_to_int(char* direction_str){
	if ((strcmp(direction_str, "In") == 0) || 
		(strcmp(direction_str, "in") == 0) ){
		return 0x01;
	} else if ((strcmp(direction_str, "Out") == 0) || 
		(strcmp(direction_str, "out") == 0)){
		return 0x02;
	} else if((strcmp(direction_str, "Any") == 0) || 
		(strcmp(direction_str, "any") == 0)){
		return (0x01 | 0x02);
	} 
	return -1;
}



int ack_str_to_int(char* ack_str){
	if ((strcmp(ack_str, "Yes") == 0) || 
		(strcmp(ack_str, "yes") == 0) ){
		return 0x02;
	} else if ((strcmp(ack_str, "No") == 0) || 
		(strcmp(ack_str, "no") == 0)){
		return 0x01;
	} else if((strcmp(ack_str, "Any") == 0) || 
		(strcmp(ack_str, "any") == 0)){
		return (0x01 | 0x02);
	} 
	return -1;
}

int action_str_to_int(char* action_str){
		if ((strcmp(action_str, "Drop") == 0) || 
		(strcmp(action_str, "drop") == 0) ){
		return 0;
	} else if ((strcmp(action_str, "Accept") == 0) || 
		(strcmp(action_str, "accept") == 0)){
		return 1;
	} 
	return -1;
}

unsigned int prefix_size_to_mask(unsigned char prefix_size){
	return ((0xFFFFFFFF << (32 - prefix_size)) & 0xFFFFFFFF);
}

