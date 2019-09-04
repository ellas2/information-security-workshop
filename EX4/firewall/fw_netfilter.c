#include <linux/module.h> 
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/netdevice.h>
#include <linux/string.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/time.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/ctype.h>
#include <net/tcp.h>

#include "fw.h"
#include "fw_rules.h"
#include "fw_log.h"
#include "fw_con_table.h"

#define IN_MASK 4294967040u //255.255.255.0
#define IN_NET 167772417u //10.0.1.1
#define IN_NET_NIC "eth0"
#define OUT_NET_NIC "eth1"


static struct nf_hook_ops nf_prerout;
static struct nf_hook_ops nf_output;


void reeval_checksum(struct sk_buff *skb, struct iphdr *ip_header, struct tcphdr *tcp_header){
	int tcplen = (skb->len - ((ip_header->ihl)<<2)); 
	tcp_header->check = 0;
	tcp_header->check = tcp_v4_check(tcplen, ip_header->saddr, ip_header->daddr, csum_partial((char*)tcp_header, tcplen, 0));
	skb->ip_summed = CHECKSUM_NONE; //stop offloading
	ip_header->check = 0;
	ip_header->check = ip_fast_csum((u8 *)ip_header, ip_header->ihl);	
}

	
unsigned int hook_func_prerout(unsigned int hooknum, struct sk_buff *skb,
 		const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)){
	//get src address, src netmask, src port, dest ip, dest netmask, dest port, protocol
   ack_t ack = ACK_ANY;//will only be relevant for TCP
   direction_t direction = DIRECTION_ANY;
   int i;
   unsigned int is_existing_con[3] = {0,0,0};
   unsigned long curr_time;
   struct timeval time;
   struct iphdr *ip_header;
   struct tcphdr *tcp_header;
   struct udphdr *udp_header;
   do_gettimeofday(&time);
   unsigned int src_port = PORT_ANY, dst_port = PORT_ANY;
   unsigned short fin = 0, syn = 0;//will only be relevant for TCP
   curr_time = (u32)(time.tv_sec - ((sys_tz.tz_minuteswest + 120)* 60));
   if (!skb)
		return NF_DROP;
   ip_header = (struct iphdr *)skb_network_header(skb);
   if (!ip_header)
		return NF_DROP;
   //get src and dest ip addresses
   unsigned int src_ip = ntohl(ip_header->saddr);
   unsigned int dst_ip = ntohl(ip_header->daddr);
   //get src and dest port number
   if (ip_header->protocol == PROT_UDP){
       udp_header = (struct udphdr *)skb_transport_header(skb);
  	   src_port = ntohs(udp_header->source);
       dst_port = ntohs(udp_header->dest);
   } else if (ip_header->protocol == PROT_TCP){
	   tcp_header = (struct tcphdr*)(skb->data + ip_header->ihl * 4);
       if (!tcp_header)
       		return NF_DROP;
       src_port = ntohs(tcp_header->source);
       dst_port = ntohs(tcp_header->dest);
       if (tcp_header->ack == 0){
       		ack = ACK_NO;
       } else {
       		ack = ACK_YES;
       }
       if (tcp_header->fin){
       		fin = 1;
       } else {
       		fin = 0;
       }
       if (tcp_header->syn){
       		syn = 1;
       } else {
       		syn = 0;
       }
       //xmas tree
       if (fin && tcp_header->urg && tcp_header->psh){
          if((add_to_logs(curr_time, PROT_TCP, NF_DROP, 
        hooknum, src_ip, dst_ip, src_port, dst_port, REASON_XMAS_PACKET)) != 0){
            printk("Unable to add to log\n");
          }
       		printk("in prerouting - dropping packet\n");
   			return NF_DROP;
       }
       
    } else{//not UDP or TCP - can be ICMP or any other protocol
      	src_port = PORT_ANY;
        dst_port = PORT_ANY;
	}
	printk("\nin prerouting with protocol %d:\n src_ip: %u, src_port: %hu, dst_ip: %u, dst_port: %hu\n", ip_header->protocol, src_ip, src_port, dst_ip, dst_port);
    printk("ack:%x, syn: %d, fin: %d\n", ack, syn, fin);
   
   //get direction
   
   if ((src_ip & IN_MASK) == IN_NET){
   		direction = DIRECTION_IN;
   } else if ((dst_ip & IN_MASK) == IN_NET){
   		direction = DIRECTION_OUT;
   } else {
   		direction = DIRECTION_ANY;
   }
   //FW is down - no need to check the rules - 
   //just add to logs with the reason REASON_FW_INACTIVE and accept the packet
   if (!(is_fw_active())){
    if ((add_to_logs(curr_time, ip_header->protocol, NF_ACCEPT, hooknum, src_ip, dst_ip, src_port, dst_port, REASON_FW_INACTIVE)) != 0){
        printk("Unable to add to log\n");
      }
   		printk("fw inactive - accepting packet\n");
   		return NF_ACCEPT;
   }
   
   //******************NON-TCP PACKETS**********************************
   if (ip_header->protocol != PROT_TCP){
   		printk("NON TCP PACKET\n");
	   //go over the static rule table
	   printk("num rules is: %d\n", num_rules());
	   printk("rule comparison arguments are:\n");
	   if (direction == DIRECTION_OUT){
	   		printk("direction is out\n");
	   } else {

	   } printk("direction is in\n");
	   printk("protocol: %hhu\n, ack: %x", ip_header->protocol, ack);
	   for (i = 0; i < num_rules(); i++){
	   		//if a match is found - register it in the logs
	   		//and decide according to action in rule table

	   		if (compare_to_rule(i, direction, src_ip, dst_ip, ip_header->protocol, 
	   								ack, src_port, dst_port) == 0){
          if ((add_to_logs(curr_time, ip_header->protocol, rules[i].action, 
                    hooknum, src_ip, dst_ip, src_port, dst_port, i)) != 0){
            printk("Unable to add to log\n");
          }
	   			printk("non TCP: in prerouting - decission is according to static rule table\n");
	   			return rules[i].action;
	   		}
	   }
	   //no matching rule found - 
	   //add to logs that the packet has been accepted and accept it!
     if ((add_to_logs(curr_time, ip_header->protocol, NF_ACCEPT, hooknum, src_ip, dst_ip, src_port, dst_port, REASON_NO_MATCHING_RULE)) != 0){
        printk("Unable to add to log\n");       
    }
		printk("non TCP: in prerouting - no rule found - accepting packet\n");
		return NF_ACCEPT;
		
	//****************TCP PACKETS WITH ACK = 0****************************
   //we need to consult the static tule table
   } else if (syn && (ack == ACK_NO) && (src_port != 20)){
   		printk("TCP PACKET with ACK = 0\n");
   		//go over the rules and look for a match -
	    //if a match is found - register in logs and then "decide"
   		//if the action in the rule table is to accept - add the packet to the connection table
	   for (i = 0; i < num_rules(); i++){
	   		//if a match is found - decide according to action in rule table
	   		if (compare_to_rule(i, direction, src_ip, dst_ip, ip_header->protocol, ack, src_port, dst_port) == 0){
	   			if ((add_to_logs(curr_time, ip_header->protocol, rules[i].action, hooknum, src_ip, dst_ip, src_port, dst_port, i)) != 0){
	   				printk("Unable to add to log\n");
	   			}
          //static rule table says drop - shouldn't add to connection table
          if (rules[i].action == NF_DROP){
            return rules[i].action;
          } 
          if (tcp_header->dest == htons(20) || tcp_header->source == htons(20)){
            add_new_conn_row(src_ip, dst_ip, src_port, dst_port, EXPECTED_FTP, i);
          } else {
            add_new_conn_row(src_ip, dst_ip, src_port, dst_port, SYN_SENT, i);
          }
	   			printk("TCP with ack = 0: in prerouting - decission is according to static rule table\n");
          break;
	   		}
	   }
	   //no matching rule found - default rule is accept
     if ((add_to_logs(curr_time, ip_header->protocol, NF_ACCEPT, hooknum, src_ip, dst_ip, src_port, dst_port, REASON_NO_MATCHING_RULE)) != 0){
        printk("Unable to add to log\n");
      }
    if (tcp_header->dest == htons(20) || tcp_header->source == htons(20)){
        add_new_conn_row(src_ip, dst_ip, src_port, dst_port, EXPECTED_FTP, i);
    } else {
        add_new_conn_row(src_ip, dst_ip, src_port, dst_port, SYN_SENT, i);
    }		
      //add_new_conn_row(dst_ip, src_ip, dst_port, src_port, SYN_SENT, REASON_DEFAULT_ACCEPT);
	    printk("TCP with ack = 0: in prerouting - no rule found - accepting packet\n");
	  //****************TCP PACKETS WITH ACK = 1 AND FTP SERVER*****************************
	} else {
		printk("TCP PACKET with ACK = 1 OR FTP SERVER WITH SYN = 1\n");
		printk("ack:%x, syn: %d\n", ack, syn);
		//need to check whether this connection exists and if it does - 
		//check whether it fits the state machine of TCP
    check_packet_with_con_table(ip_header->protocol, is_existing_con, src_ip, dst_ip, src_port, dst_port, ack, syn, fin, (unsigned long)ntohl(tcp_header->rst));
    if ((add_to_logs(curr_time, ip_header->protocol, is_existing_con[0], hooknum, src_ip, dst_ip, src_port, dst_port, is_existing_con[1])) != 0){
        printk("Unable to add to log\n");
    }
   	if ((is_existing_con[2] != 1) && (is_existing_con[0] != NF_ACCEPT)){
   		printk("TCP with ack = 1 or ftp with syn = 1: in prerouting - dropping packet\n");
   		return NF_DROP;
   	}
	}
	//****************************HTTP************************************
	if (tcp_header->dest == htons(80)){
			printk("DST PORT 80\n");
			//change the routing - http proxy
      ip_header->daddr = htonl(ip_str_to_hl("10.0.1.3"));//proxy's ip
			tcp_header->dest = htons(8007);//proxy's listening port
			//checksum re-evalutaion
			reeval_checksum(skb, ip_header, tcp_header);
			printk("TCP with ack = 1: in prerouting - changing the routing to http proxy - ip 10.0.1.3, port 8007\n");
	} else if (tcp_header->source == htons(80)){
			printk("SRC PORT 80\n");
			//change the routing - proxy
			ip_header->daddr = htonl(ip_str_to_hl("10.0.2.3"));//proxy's ip
			tcp_header->dest = htons(get_proxy_port(src_ip, src_port));//proxy's listening port
			//checksum re-evalutaion
			reeval_checksum(skb, ip_header, tcp_header);
			printk("TCP with ack = 1: in prerouting - changing the routing to http proxy - ip 10.0.2.3, port %hu\n", get_proxy_port(src_ip, src_port));
	//**************************SMTP*********************************
  } if (tcp_header->dest == htons(25)){
      printk("DST PORT 25\n");
      //change the routing - smtp proxy
      ip_header->daddr = htonl(ip_str_to_hl("10.0.1.3"));//proxy's ip
      tcp_header->dest = htons(8006);//proxy's listening port
      //checksum re-evalutaion
      reeval_checksum(skb, ip_header, tcp_header);
      printk("TCP with ack = 1: in prerouting - changing the routing to http proxy - ip 10.0.1.3, port 8006\n");
  } else if (tcp_header->source == htons(25)){
      printk("SRC PORT 25\n");
      //change the routing - proxy
      ip_header->daddr = htonl(ip_str_to_hl("10.0.2.3"));//proxy's ip
      tcp_header->dest = htons(get_proxy_port(src_ip, src_port));//proxy's listening port
      //checksum re-evalutaion
      reeval_checksum(skb, ip_header, tcp_header);
      printk("TCP with ack = 1: in prerouting - changing the routing to http proxy - ip 10.0.2.3, port %hu\n", get_proxy_port(src_ip, src_port));
  //****************************FTP1********************************
	} else if (tcp_header->dest == htons(21)){
			printk("DST PORT 21\n");
			//change the routing - ftp proxy
			ip_header->daddr = htonl(ip_str_to_hl("10.0.1.3"));//proxy's ip
			tcp_header->dest = htons(8008);//proxy's listening port
			//checksum re-evalutaion
			reeval_checksum(skb, ip_header, tcp_header);
			printk("TCP with ack = 1: in prerouting - changing the routing to ftp proxy - ip 10.0.1.3, port 8008\n");
	} else if (tcp_header->source == htons(21)){
			printk("SRC PORT 21\n");
			//change the routing - ftp proxy
			ip_header->daddr = htonl(ip_str_to_hl("10.0.2.3"));//proxy's ip
			tcp_header->dest = htons(get_proxy_port(src_ip, src_port));//proxy's listening port
			//checksum re-evalutaion
			reeval_checksum(skb, ip_header, tcp_header);
			printk("TCP with ack = 1: in prerouting - changing the routing to ftp proxy - ip 10.0.2.3, port %hu\n", get_proxy_port(src_ip, src_port));
	} else if (tcp_header->dest == htons(20)){
			printk("DST PORT 20\n");
			//change the routing - ftp proxy
			ip_header->daddr = htonl(ip_str_to_hl("10.0.1.3"));//proxy's ip
			tcp_header->dest = htons(get_proxy_port(src_ip, src_port));//proxy's listening port
			//checksum re-evalutaion
			reeval_checksum(skb, ip_header, tcp_header);
			printk("TCP with ack = 1: in prerouting - changing the routing to ftp proxy - ip 10.0.1.3, port %hu\n", get_proxy_port(src_ip, src_port));
	} else if (tcp_header->source == htons(20)){
			printk("SRC PORT 20\n");
			//change the routing - ftp proxy
			ip_header->daddr = htonl(ip_str_to_hl("10.0.2.3"));//proxy's ip
			tcp_header->dest = htons(8009);//proxy's listening port
			//checksum re-evalutaion
			reeval_checksum(skb, ip_header, tcp_header);
			printk("TCP with ack = 1: in prerouting - changing the routing to ftp proxy - ip 10.0.2.3, port 8009\n");
	}
		return NF_ACCEPT;
}


unsigned int hook_func_output(unsigned int hooknum, struct sk_buff *skb,
 		const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)){
	
	//get src address, src netmask, src port, dest ip, dest netmask, dest port, protocol
   ack_t ack = ACK_ANY;//will only be relevant for TCP
   direction_t direction;
   int i;
   unsigned int is_existing_con[3] = {0,0,0};
   unsigned long curr_time;
   struct timeval time;
   struct iphdr *ip_header;
   struct tcphdr *tcp_header;
   struct udphdr *udp_header;
   do_gettimeofday(&time);
   unsigned int src_port = PORT_ANY, dst_port = PORT_ANY;
   unsigned short fin = 0, syn = 0, temp_proxy_port = 0;//will only be relevant for TCP
   curr_time = (u32)(time.tv_sec - ((sys_tz.tz_minuteswest + 120)* 60));
   if (!skb)
		return NF_DROP;
   ip_header = (struct iphdr *)skb_network_header(skb);
   if (!ip_header)
		return NF_DROP;
   //get src and dest ip addresses
   unsigned int src_ip = ntohl(ip_header->saddr);
   unsigned int src_ip_net = ip_header->saddr;
   unsigned int dst_ip = ntohl(ip_header->daddr);
   unsigned int dst_ip_net = ip_header->daddr;
   //get src and dest port number
   if (ip_header->protocol == PROT_UDP){
       udp_header = (struct udphdr *)skb_transport_header(skb);
  	   src_port = ntohs(udp_header->source);
       dst_port = ntohs(udp_header->dest);
   } else if (ip_header->protocol == PROT_TCP){
	   tcp_header = (struct tcphdr*)(skb->data + ip_header->ihl * 4);
       if (!tcp_header)
       		return NF_DROP;
       src_port = ntohs(tcp_header->source);
       dst_port = ntohs(tcp_header->dest);
       if (tcp_header->ack == 0){
       		ack = ACK_NO;
       } else {
       		ack = ACK_YES;
       }
       if (tcp_header->fin){
       		fin = 1;
       } else {
       		fin = 0;
       }
       if (tcp_header->syn){
       		syn = 1;
       } else {
       		syn = 0;
       }
       //xmas tree
       if (fin && tcp_header->urg && tcp_header->psh ){
       		if((add_to_logs(curr_time, PROT_TCP, NF_DROP, 
 				hooknum, src_ip_net, dst_ip_net, src_port, dst_port, REASON_XMAS_PACKET)) != 0){
       			printk("Unable to add to log\n");
       		}
       		printk("in output hook - dropping packet\n");
   			return NF_DROP;
       }
       
   } else{//not UDP or TCP - can be ICMP or any other protocol
      	src_port = PORT_ANY;
   		dst_port = PORT_ANY;
	}
	printk("\nin output with protocol %d:\n src_ip: %u, src_port: %hu, dst_ip: %u, dst_port: %hu\n", ip_header->protocol, src_ip, src_port, dst_ip, dst_port);
    printk("ack:%x, syn: %d, fin: %d\n", ack, syn, fin);  //get direction
   
   if ((src_ip & IN_MASK) == IN_NET){
   		direction = DIRECTION_IN;
   } else if ((dst_ip & IN_MASK) == IN_NET){
   		direction = DIRECTION_OUT;
   } else {
   		direction = DIRECTION_ANY;
   }
    
   //FW is down - no need to check the rules - 
   //just add to logs with the reason REASON_FW_INACTIVE and accept the packet
   if (!(is_fw_active())){
      if ((add_to_logs(curr_time, ip_header->protocol, NF_ACCEPT, 
        hooknum, src_ip, dst_ip, src_port, dst_port, REASON_FW_INACTIVE)) != 0){
        printk("Unable to add to log\n");
      }
   		printk("fw inactive - in output hook - accepting packet\n");
   		return NF_ACCEPT;
   }
   
   //******************NON-TCP PACKETS**********************************
   if (ip_header->protocol != PROT_TCP){
   		printk("NON TCP PACKET\n");
	   //go over the static rule table
	   for (i = 0; i < num_rules(); i++){
	   		//if a match is found - register it in the logs
	   		//and decide according to action in rule table
	   		if (compare_to_rule(i, direction, src_ip, dst_ip, ip_header->protocol, 
	   				ack, src_port, dst_port) == 0){
          if ((add_to_logs(curr_time, ip_header->protocol, rules[i].action, 
              hooknum, src_ip, dst_ip, src_port, dst_port, i)) != 0){
            printk("Unable to add to log\n");
          }
	   			printk("non TCP: in output hook - decission is according to static rule table\n");
	   			return rules[i].action;
	   		}
	   }
	   //no matching rule found - 
	   //add to logs that the packet has been accepted and accept it!
     if ((add_to_logs(curr_time, ip_header->protocol, NF_ACCEPT, 
            hooknum, src_ip, dst_ip, src_port, dst_port, 
            REASON_NO_MATCHING_RULE)) != 0){
        printk("Unable to add to log\n");
        
    }
		printk("non TCP: in prerouting - no rule found - accepting packet\n");
		return NF_ACCEPT;
	}
	//****************************HTTP************************************
	if (tcp_header->dest == htons(80)){
			printk("DST PORT 80\n");
			temp_proxy_port = src_port;//for later
			//change the routing 
			ip_header->saddr = htonl(get_actual_ip(dst_ip, dst_port, 1));
			src_ip = get_actual_ip(dst_ip, dst_port, 1);
			tcp_header->source = htons(get_actual_port(dst_ip, dst_port, 1));
			src_port = get_actual_port(dst_ip, dst_port, 1);
			//checksum re-evalutaion
			reeval_checksum(skb, ip_header, tcp_header);
			printk("dest is port 80, src ip is now: %u and src port is now: %hu\n", 
				src_ip, src_port);
	} else if (tcp_header->source == htons(8007)){
			printk("SRC PORT 8007\n");
			//change the routing
			ip_header->saddr = htonl(get_actual_ip(dst_ip, dst_port, 0));
			src_ip = get_actual_ip(dst_ip, dst_port, 0);
			tcp_header->source = htons(get_actual_port(dst_ip, dst_port, 0)); 
			src_port = get_actual_port(dst_ip, dst_port, 0);
			//checksum re-ecalutaion
			reeval_checksum(skb, ip_header, tcp_header);
			printk("source is port 8007, src ip is now: %u and src port is now: %hu\n", 
				src_ip, src_port);

  //****************************SMTP*****************************//
  } else if (tcp_header->dest == htons(25)){//ftp21
      printk("DST PORT 25\n");
      temp_proxy_port = src_port;//for later
      //change the routing 
      ip_header->saddr = htonl(get_actual_ip(dst_ip, dst_port, 1));
      src_ip = get_actual_ip(dst_ip, dst_port, 1);
      tcp_header->source = htons(get_actual_port(dst_ip, dst_port, 1));
      src_port = get_actual_port(dst_ip, dst_port, 1);
      //checksum re-evalutaion
      reeval_checksum(skb, ip_header, tcp_header);
      printk("dest is port 25, src ip is now: %u and src port is now: %hu\n", 
        src_ip, src_port);
  } else if (tcp_header->source == htons(8006)){//ftp21
      printk("DST PORT 25\n");
      temp_proxy_port = src_port;//for later
      //change the routing 
      ip_header->saddr = htonl(get_actual_ip(dst_ip, dst_port, 0));
      src_ip = get_actual_ip(dst_ip, dst_port, 0);
      tcp_header->source = htons(get_actual_port(dst_ip, dst_port, 0));
      src_port = get_actual_port(dst_ip, dst_port, 0);
      //checksum re-evalutaion
      reeval_checksum(skb, ip_header, tcp_header);
      printk("dest is port 25, src ip is now: %u and src port is now: %hu\n", 
        src_ip, src_port);
  
	//****************************FTP1********************************
	} else if (tcp_header->dest == htons(21)){//ftp21
			printk("DST PORT 21\n");
			temp_proxy_port = src_port;//for later
			//change the routing 
			ip_header->saddr = htonl(get_actual_ip(dst_ip, dst_port, 1));
			src_ip = get_actual_ip(dst_ip, dst_port, 1);
			tcp_header->source = htons(get_actual_port(dst_ip, dst_port, 1));
			src_port = get_actual_port(dst_ip, dst_port, 1);
			//checksum re-evalutaion
			reeval_checksum(skb, ip_header, tcp_header);
			printk("dest is port 21, src ip is now: %u and src port is now: %hu\n", 
				src_ip, src_port);
	} else if (tcp_header->source == htons(8008)){
			printk("SRC PORT 8008\n");
			//change the routing
			ip_header->saddr = htonl(get_actual_ip(dst_ip, dst_port, 0));
			src_ip = get_actual_ip(dst_ip, dst_port, 0);
			tcp_header->source = htons(get_actual_port(dst_ip, dst_port, 0));
			src_port = get_actual_port(dst_ip, dst_port, 0);
			//checksum re-evalutaion
			reeval_checksum(skb, ip_header, tcp_header);
			printk("source is port 8008, src ip is now: %u and src port is now: %hu\n", 
				src_ip, src_port);
	} else if (tcp_header->source == htons(8009)){//ftp20
			printk("SRC PORT 8009\n");
			//change the routing
			ip_header->saddr = htonl(get_actual_ip(dst_ip, dst_port, 0));
			src_ip = get_actual_ip(dst_ip, dst_port, 0);
			tcp_header->source = htons(get_actual_port(dst_ip, dst_port, 0)); 
			src_port = get_actual_port(dst_ip, dst_port, 0);
			//checksum re-evalutaion
			reeval_checksum(skb, ip_header, tcp_header);
			printk("source is port 8009, src ip is now: %u and src port is now: %hu\n", 
				src_ip, src_port);
	} else {
			update_proxy_port(dst_ip,dst_port,src_port);
			temp_proxy_port = src_port;//for later
			//change the routing 
			ip_header->saddr = htonl(get_actual_ip(dst_ip, dst_port, 1));
			src_ip = get_actual_ip(dst_ip, dst_port, 1);
			tcp_header->source = htons(get_actual_port(dst_ip, dst_port, 1));
			src_port = get_actual_port(dst_ip, dst_port, 1);
			//checksum re-evalutaion
			reeval_checksum(skb, ip_header, tcp_header);
			printk("ftp20 proxy port out, src ip is now: %u and src port is now: %hu\n", 
					src_ip, src_port);
	}
	//****************TCP PACKETS WITH ACK = 0****************************
   //we need to consult the static tule table
    if (syn && (ack == ACK_NO) && (src_port != 20)){
    	printk("TCP PACKET with ACK = 0\n");
   		//go over the rules and look for a match -
	    //if a match is found - register in logs and then "decide"
   		//if the action in the rule table is to accept - add the packet to the connection table
	    for (i = 0; i < num_rules(); i++){
	   		//if a match is found - decide according to action in rule table
	   		if (compare_to_rule(i, direction, src_ip, dst_ip, ip_header->protocol, 
	   			ack, src_port, dst_port) == 0){
          if ((add_to_logs(curr_time, ip_header->protocol, rules[i].action, 
              hooknum, src_ip, dst_ip, src_port, dst_port, i)) != 0){
            printk("Unable to add to log\n");
          }
          if (rules[i].action != NF_DROP){
              if (tcp_header->dest == htons(20) || tcp_header->source == htons(20)){
                  add_new_conn_row(dst_ip, src_ip, dst_port, src_port, EXPECTED_FTP, i);
              } else {
                  add_new_conn_row(dst_ip, src_ip, dst_port, src_port, SYN_SENT, i);

              }  
          }
	   			update_proxy_port(dst_ip,dst_port,temp_proxy_port);
          if (rules[i].action == NF_DROP){
              return rules[i].action;
          }
	   			printk("TCP with ack = 0: in output hook - decission is according to static rule table\n");
	   		}
	   		
	    }
	   //no matching rule found - default rule is accept
      if ((add_to_logs(curr_time, ip_header->protocol, NF_ACCEPT, 
            hooknum, src_ip, dst_ip, src_port, dst_port, 
            REASON_NO_MATCHING_RULE)) != 0){
        printk("Unable to add to log\n");
      }
      if (tcp_header->dest == htons(20) || tcp_header->source == htons(20)){
           add_new_conn_row(dst_ip, src_ip, dst_port, src_port, EXPECTED_FTP, i);
      } else {
          add_new_conn_row(dst_ip, src_ip, dst_port, src_port, SYN_SENT, i);
      }
	   	update_proxy_port(dst_ip,dst_port,temp_proxy_port);
	    printk("TCP with ack = 0: in output hook - no rule found - accepting packet\n");
	   	//return NF_ACCEPT;
		//****************TCP PACKETS WITH ACK = 1*****************************
		} else {
			printk("TCP PACKET with ACK = 1\n");
      /*
			if ((tcp_header->source == htons(80)) || (tcp_header->source == htons(21)) ||
						(tcp_header->source == htons(20)) || (tcp_header->dest == htons(20))){
              */
      if ((tcp_header->source == htons(80)) || (tcp_header->dest == htons(80)) ||(tcp_header->source == htons(21)) ||
            (tcp_header->source == htons(20)) || (tcp_header->dest == htons(20))){
				printk("output - src 80/21/20 or dest 20- check with connection table\n");
				//need to check whether this connection exists and if it does - 
				//check whether it fits the state machine of TCP
				check_packet_with_con_table(ip_header->protocol, is_existing_con, dst_ip, src_ip, dst_port, src_port, 
													ack, syn, fin, (unsigned long)ntohl(tcp_header->rst));
        if ((add_to_logs(curr_time, ip_header->protocol, is_existing_con[0], 
                  hooknum, dst_ip, src_ip, dst_port, src_port, is_existing_con[1])) != 0){
            printk("Unable to add to log\n");
          }
			} else {
				printk("output dest not 20 and src not 80,21,20- \n");
				check_packet_with_con_table(ip_header->protocol, is_existing_con, src_ip, dst_ip, src_port, dst_port, 
													ack, syn, fin, (unsigned long)ntohl(tcp_header->rst));
        if ((add_to_logs(curr_time, ip_header->protocol, is_existing_con[0], 
                  hooknum, src_ip, dst_ip, src_port, dst_port, is_existing_con[1])) != 0){
            printk("Unable to add to log\n");
          }
			}
		   	if ((is_existing_con[2] != 1) && (is_existing_con[0] != NF_ACCEPT)){
		   		printk("TCP with ack = 1: in output hook - dropping packet\n");
		   		return NF_DROP;
		   	}
		}
	   
		return NF_ACCEPT;
}
	
void netfilter_init(void){
	//registering the prerouting hook 
	nf_prerout.hook = hook_func_prerout;
	nf_prerout.hooknum = NF_INET_PRE_ROUTING;
	nf_prerout.pf = PF_INET;
	nf_prerout.priority = 1;
	nf_register_hook(&nf_prerout);
	//registering the prerouting hook 
	nf_output.hook = hook_func_output;
	nf_output.hooknum = NF_INET_LOCAL_OUT;
	nf_output.pf = PF_INET;
	nf_output.priority = 2;
	nf_register_hook(&nf_output);

}

void netfilter_cleanup(void){
	nf_unregister_hook(&nf_output);
	nf_unregister_hook(&nf_prerout);
}

