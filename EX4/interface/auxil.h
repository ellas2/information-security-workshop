#ifndef AUXIL_H_
#define AUXIL_H_


char* reason_int_to_str(int reason_int);

char* protocol_int_to_str(int protocol_int);

char* direction_int_to_str(int direction_int);

char* ack_int_to_str(int ack_int);

char* action_int_to_str(int action_int);

unsigned int ip_str_to_hl(char* ip_str);

int protocol_str_to_int(char* protocol_str);

int direction_str_to_int(char* direction_str);

int ack_str_to_int(char* ack_str);

int action_str_to_int(char* action_str);

unsigned int prefix_size_to_mask(unsigned char prefix_size);


#endif /*AUXIL_H_*/