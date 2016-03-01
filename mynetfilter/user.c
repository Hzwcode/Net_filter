#include <stdio.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <fcntl.h>

int main(void){
	int fd;
	fd = open("/dev/memdev", O_RDWR);
	if(fd < 0){
		perror("open");
		return -1;
	}
	close(fd);
	return 0;
}