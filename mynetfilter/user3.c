#include <stdio.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <getopt.h>
#include <fcntl.h>
#include <string.h>

int main(void){
	FILE *fp0 = NULL;
	FILE *fp1 = NULL;
	//char buf[80] = "10.11.55.176 /24 0.0.0.0 /24 65535 65535 255 08:00:00 17:00:00 1 1";
	char buf[80];
	int num, i;
 	/*打开设备文件*/
 	if((fp0 = fopen("/dev/memdev","a+")) == NULL)
 	{
 	   printf("open memdev error!\n");
 	   return -1;
 	}
 	if((fp1 = fopen("rule.txt","r+")) == NULL){
 		printf("open rule.txt error!\n");
 	   return -1;
 	}
 	fgets(buf, 80, fp1);
 	sscanf(buf, "%d", &num);
 	printf("num:  %d\n", num);
 	fprintf(fp0, "%s", buf);
 	for(i = 0; i < num; i++){
 		fgets(buf, 80, fp1);
 		printf("<u_row %d>: %s\n", i+1, buf);
 		fprintf(fp0, "%s", buf);
 	}
 	fclose(fp1);
 	fseek(fp0, 0, SEEK_SET);
 	for(i = 0; i < num; i++){
 		fgets(buf, 80, fp0);
 		printf("<row %d>: %s\n", i+1, buf);
 	}
 	
 	//fread(buf2, sizeof(buf2), 1, fp0);
 	//printf("BUF: %s\n",buf2);
 	fclose(fp0);
 	/*写入设备*/
 	//fwrite(buf, sizeof(buf), 1, fp0);
 	/*重新定位文件位置（思考没有该指令，会有何后果)*/
 	//fseek(fp0, 0, SEEK_SET);//调用mem_llseek（）定位
 	/*清除Buf*/
 	//strcpy(buf,"Buf is NULL!");
 	//printf("BUF: %s\n",buf);
 	/*读出设备*/
 	//fread(buf, sizeof(buf), 1, fp0);
 	/*检测结果*/
 	//printf("BUF: %s\n",buf);
 
	return 0;
}