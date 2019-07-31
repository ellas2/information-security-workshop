#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char** argv){
	int fd;
	char accepted_buf[4];
	char dropped_buf[4];
	int accepted = 0;
	int dropped = 0;

	if((fd = open("/sys/class/sysfs_class/sysfs_class_sysfs_device/sysfs_att", O_RDWR)) < 0){
		printf("Cannot open device file\n");
		exit(-1);	
	}

	if(argc > 2){
		printf("Invalid number of arguments");
		exit(-1);
	} else if (argc == 2){// we need to check for ZERO
		//As there are no clear instructions on what to do with non-zero
		//inputs, I decided to terminate the program instead of 
		//ignoring them
		if (atoi(argv[1]) != 0){
			printf("Argument can only be zero :-(");
			exit(-1);
		}
		if (write(fd, "0", 4) == -1){
			printf("Error while writing to device file\n");
			exit(-1);	
		}
	}

	//we read the number of accpeted packets from the sysfs device
	if(read(fd, accepted_buf, 4) == -1){
		printf("Error while reading from device file\n");
		exit(-1);	
	}
	accepted = atoi(accepted_buf);

	//I had to close the sysfs file and reopen it - otherwise the second read did not work properly
	close(fd);
	if((fd = open("/sys/class/sysfs_class/sysfs_class_sysfs_device/sysfs_att", O_RDWR)) < 0){
		printf("Cannot open device file\n");
		exit(-1);	
	}
	//we read the number of dropped packets from the sysfs device
	if(read(fd, dropped_buf, 4) == -1){
		printf("Error while reading from device file\n");
		exit(-1);	
	}
	dropped = atoi(dropped_buf);

	printf("Firewall Packets Summary:\n");
	printf("Number of accepted packets: %d\n", accepted);
	printf("Number of dropped packets: %d\n", dropped);
	printf("Total number of packets: %d\n", accepted + dropped);

	close(fd);
}
