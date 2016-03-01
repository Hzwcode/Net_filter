#include <stdio.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <getopt.h>
#include <fcntl.h>
#include <string.h>

int main(void){
	FILE *fp0 = NULL;
	char buf[4096];
	//初始化buff
	strcpy(buf,"Mem is char dev!");
 	printf("BUF: %s\n",buf);
 
 	/*打开设备文件*/
 	fp0 = fopen("/dev/memdev","r+");
 	if(fp0 == NULL)
 	{
 	   printf("open memdev error!\n");
 	   return -1;
 	}
 
 	/*写入设备*/
 	fwrite(buf, sizeof(buf), 1, fp0);
 
 	/*重新定位文件位置（思考没有该指令，会有何后果)*/
 	fseek(fp0, 0, SEEK_SET);//调用mem_llseek（）定位
 
 	/*清除Buf*/
 	strcpy(buf,"Buf is NULL!");
 	printf("BUF: %s\n",buf);
 
 
 	/*读出设备*/
 	fread(buf, sizeof(buf), 1, fp0);
 
 	/*检测结果*/
 	printf("BUF: %s\n",buf);
 
	return 0;
	/*
	int fd, count;
	fd = open("/dev/memdev", O_RDWR);
	if(fd < 0){
		perror("open");
		return -1;
	}
	count = read(fd, buff1, 20);
	printf("<user>kbuf is [%s]\n", buff1);

	count = write(fd, buff2, 20);
	if(count == -1){
		perror("write");
	}

	close(fd);
	return 0;
	*/
}