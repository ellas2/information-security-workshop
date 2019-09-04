#ifndef FW_NETFILTER_H_
#define FW_NETFILTER_H_

void netfilter_init(void);

void netfilter_cleanup(void);

unsigned int hook_func_prerout(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *));

void reeval_checksum(struct sk_buff *skb, struct iphdr *ip_header, struct tcphdr *tcp_header);

unsigned int hook_func_output(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *));


#endif /*FW_NETFILTER_H_*/
