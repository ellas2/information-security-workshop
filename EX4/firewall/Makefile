obj-m += firewall.o 
firewall-objs += fw.o fw_netfilter.o fw_rules.o fw_log.o fw_con_table.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
