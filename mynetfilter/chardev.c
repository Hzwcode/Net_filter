#include "chardev.h"

MODULE_LICENSE("GPL");

unsigned int major = 254;
unsigned int minor = 0;
dev_t dev_id;
struct cdev my_cdev;
struct mem_dev *mem_devp;  //设备结构体指针
int mutex = 1;
int counter = 0;

extern struct rule rule_head;

struct file_operations rule_fops = {
	.owner = THIS_MODULE,
	.llseek = my_llseek,
	.open = my_open,
	.read = my_read,
	.write = my_write,
	.release = my_release,
};
/*
unsigned int inet2addr(char *str){
	int a,b,c,d;
	uint8_t arr[4];
	sscanf(str, "%d.%d.%d.%d", &a,&b,&c,&d);
	arr[0] = a; arr[1] =b; arr[2] = c; arr[3] = d;
	return *(unsigned int *)&arr;
}
*/
char* addr2inet(unsigned int addr){
	char *str = NULL;
	uint8_t *arr;
	unsigned a,b,c,d;
	if((str = kmalloc(20 * sizeof(char), GFP_KERNEL)) ==NULL){
		printk("kmalloc error in addr2inet\n");
		return NULL;
	}
	arr = (uint8_t *)&addr;
	a = arr[0]; b = arr[1]; c = arr[2]; d = arr[3];
	sprintf(str, "%u.%u.%u.%u",a,b,c,d);
	return str;
}

void PrintRule(void){
	struct rule *tmp;
	uint32_t addr;
	printk("-----------------------------\n");
    printk("          rule_list:         \n");
    printk("-----------------------------\n");
	list_for_each_entry(tmp, &rule_head.list, list){
        printk(" saddr:      %pI4 / %u\n", &tmp->saddr.addr, tmp->saddr.mask);
        addr = MASK_IP(tmp->saddr.addr, tmp->saddr.mask);
        printk(" mask_saddr: %pI4 \n", &addr);
        printk(" sport:      %u\n\n", tmp->sport);
        printk(" daddr:      %pI4 / %u\n", &tmp->daddr.addr, tmp->daddr.mask);
        addr = MASK_IP(tmp->daddr.addr, tmp->daddr.mask);
        printk(" mask_daddr: %pI4 \n", &addr);
        printk(" dport:      %u\n\n", tmp->dport);
        switch(tmp->protocol){
			case IPPROTO_TCP:
				printk(" protocol:   TCP\n\n");
				break;
			case IPPROTO_UDP:
				printk(" protocol:   UDP\n\n");
				break;
			case IPPROTO_ICMP:
				printk(" protocol:   ICMP\n\n");
				break;
			case ANY_PROTOCOL:
				printk(" protocol:   ANY\n\n");
				break;
			default:
				printk(" protocol:   unknow\n\n");
		}
		printk(" time_valid: %s\n", tmp->tm.valid ? "true" : "false");
        printk(" begin_time: %02d:%02d:%02d\n", tmp->tm.ltime.tm_hour, tmp->tm.ltime.tm_min, tmp->tm.ltime.tm_sec);
        printk(" end_time:   %02d:%02d:%02d\n\n", tmp->tm.rtime.tm_hour, tmp->tm.rtime.tm_min, tmp->tm.rtime.tm_sec);
        printk(" action:     %s\n\n", tmp->action ? "Permit" : "Reject");
        printk("-----------------------------\n");
    }
}

struct rule* str2rule(const char *buf){
	struct rule *tail = NULL;
	int lhour, lmin, lsec, rhour, rmin, rsec;
	uint16_t mask1, mask2, protocol;
	char saddr[30], daddr[30];
	int ret, time_valid = 0, action;
	if(buf == NULL || strlen(buf) == 0) {
		printk("Error: NULL buf in str2rule.\n");
		return NULL;
	}
	if((tail = (struct rule*)kmalloc(sizeof(struct rule), GFP_KERNEL)) == NULL){
		printk("Error: kmalloc fail in str2rule.\n");
		return NULL;
	}
	ret = sscanf(buf, "%s /%hu %s /%hu %hu %hu %hu %d:%d:%d %d:%d:%d %d %d", 
		saddr, &mask1, daddr, &mask2,
		&tail->sport, &tail->dport, &protocol,
		&lhour, &lmin, &lsec, &rhour, &rmin, &rsec, &time_valid, &action);
	if(ret < 15){
		printk("sscanf fail , only complete %d scanfs\n", ret);
	}
	tail -> saddr.addr = inet_addr(saddr);
	tail -> saddr.mask = mask1;
	tail -> daddr.addr = inet_addr(daddr);
	tail -> daddr.mask = mask2;
	tail -> protocol = protocol;
	tail -> tm.ltime.tm_hour = lhour;
	tail -> tm.ltime.tm_min = lmin;
	tail -> tm.ltime.tm_sec = lsec;
	tail -> tm.rtime.tm_hour = rhour;
	tail -> tm.rtime.tm_min = rmin;
	tail -> tm.rtime.tm_sec = rsec;
	tail -> tm.valid = time_valid;
	tail -> action = action;
	return tail;
}

int my_open(struct inode *inode, struct file *file){
	//printk("memdev open success!\n");
	struct mem_dev *dev;
	int num;
	if(mutex != 1)
		return EBUSY;
	mutex = 0;
	//获取次设备号
	num = MINOR(inode->i_rdev);
	if(num >= major)
		return -ENODEV;
	dev = &mem_devp[num];
	//将设备描述结构指针赋值给文件私有数据指针
	file->private_data = dev;
	printk("<count>%d times to call the device.\n", ++counter);
	return 0;
}

int my_release(struct inode *inode, struct file *file){
	printk("memdev release success!\n");
	mutex = 1;
	return 0;
}

ssize_t my_read(struct file *file, char __user *buf, size_t size, loff_t *ppos){
	//printk("memdev read success!\n");
	//memcpy(buf, "kernel test_data", size);
	unsigned int p = *ppos;    //p位当前读写位置
	unsigned int count = size;  //一次读取的大小
	
	struct mem_dev *dev = file->private_data;  //获得设备结构体指针

	//判断读位置是否有效
  	if(p >= MEMDEV_SIZE)  //是否超出读取范围
    	return 0;
  	if(count > MEMDEV_SIZE - p)
   	    count = MEMDEV_SIZE - p;  //count大于读取的范围，则缩小读取范围
   	//读取数据到用户空间
	if(copy_to_user(buf, (void *)(dev->data + p), count)){
		return -EFAULT;
	}
	*ppos += count;
	printk(KERN_INFO"read %d byte(s) from %d\n", count, p);
	printk("<kernel>read content is \n[%s]\n", buf);
	return count;
}

ssize_t my_write(struct file *file, const char __user *buf, size_t size, loff_t *ppos){
	//printk("memdev write success!\n");
	//char kbuf[20];
	//memcpy(kbuf, buf, size);
	unsigned int p = *ppos;
	unsigned int count = size;
	struct mem_dev *dev = file->private_data;  //获得设备结构体指针
	struct list_head *pos, *q;
	struct rule *tmp;
	int nline, off, ret, i;
	char *buffer;
	char saddr[30], daddr[30];

	if(p >= MEMDEV_SIZE)
		return 0;
	if(count > MEMDEV_SIZE - p)
		count = MEMDEV_SIZE - p;

	//从用户空间写入数据
	if(copy_from_user(dev->data + p, buf, count)){
		return -EFAULT;
	}
	*ppos += count;
	printk("dev_rule_write: success\n");
	printk(KERN_INFO"written %d byte(s) from %d\n", count, p);
	printk("<kernel>written content is \n[%s]\n", dev->data + p);

	list_for_each_safe(pos, q, &rule_head.list){
		tmp = list_entry(pos, struct rule, list);
		list_del(pos);
		kfree(tmp);
	}

	buffer = dev->data + p;
	nline = 0;
	off = 0;
	sscanf(buffer, "%d%n", &nline, &off);
	//printk("%d   %d\n", nline, off);
	buffer += off;
	for(i = 0; i < nline; ++i){
		if((tmp = (struct rule*)kzalloc(sizeof(struct rule), GFP_KERNEL)) == NULL){
			printk("Error: kmalloc fail.\n");
			break;
		}
		ret = sscanf(buffer, "%s /%hhu:%hu, %s /%hhu:%hu, %hhu, %hu, %d:%d:%d, %d:%d:%d, %hu%n", 
						  saddr, &tmp->saddr.mask, &tmp->sport,
						  daddr, &tmp->daddr.mask, &tmp->dport,
						  &tmp->protocol,
						  &tmp->tm.valid,
						  &tmp->tm.ltime.tm_hour, &tmp->tm.ltime.tm_min, &tmp->tm.ltime.tm_sec,
						  &tmp->tm.rtime.tm_hour, &tmp->tm.rtime.tm_min, &tmp->tm.rtime.tm_sec,
						  &tmp->action, &off);
		tmp -> saddr.addr = inet_addr(saddr);
		tmp -> daddr.addr = inet_addr(daddr);
		printk("%s/%hhu:%hu, %s/%hhu:%hu, %hhu, %hu, %02d:%02d:%02d, %02d:%02d:%02d, %hu\n", 
				saddr, tmp->saddr.mask, tmp->sport,
				daddr, tmp->daddr.mask, tmp->dport,
				tmp->protocol,
				tmp->tm.valid,
				tmp->tm.ltime.tm_hour, tmp->tm.ltime.tm_min, tmp->tm.ltime.tm_sec,
				tmp->tm.rtime.tm_hour, tmp->tm.rtime.tm_min, tmp->tm.rtime.tm_sec,
				tmp->action);
		if(ret < 15){
			printk("sscanf fail , only complete %d scanfs\n", ret);
		}
		buffer += off;
		list_add_tail(&(tmp->list), &(rule_head.list));
	}

	PrintRule();
	
	return count;
}

loff_t my_llseek(struct file *file, loff_t offset, int whence){
	loff_t newpos;
	switch(whence){
	  case 0: /* SEEK_SET */
        newpos = offset;//从文件头开始定位
        break;
      case 1: /* SEEK_CUR */
        newpos = file->f_pos + offset;//从文件中间定位
        break;
      case 2: /* SEEK_END */
        newpos = MEMDEV_SIZE -1 + offset;//从文件尾开始定位，由于是从0开始，所以要减1
        break;
      default: /* can't happen */
        return -EINVAL;
	}
	if((newpos < 0) || (newpos > MEMDEV_SIZE))
		return -EINVAL;
	file->f_pos = newpos;  //返回当前文件位置
	return newpos;
}

int dev_init(void){
	int ret = 0;
	int i;
	dev_id = MKDEV(major, minor);//MKDEV是将主设备号和次设备号转换为dev_t类型数据,参数mem_major在头文件中预设为254

	//1.申请设备号
	//如果主设备号不为0，使用静态申请一个设备号
	if(major){
		ret = register_chrdev_region(dev_id, MEMDEV_NR_DEVS, "memdev");	        //静态注册设备号
		if(ret < 0){
			ret = alloc_chrdev_region(&dev_id, minor, MEMDEV_NR_DEVS, "memdev");	//静态注册失败，动态注册设备号
			if(ret < 0){
				printk("register devno error!\n");
				//return -EBUSY;
				return ret;
			}
			printk("dynamic1 register devno success!\n");
			major = MAJOR(dev_id);
			minor = MINOR(dev_id);
		}
		else{
			printk("static register devno success!\n");
		}
	}
	//否则由内核动态分配
	else{
		ret = alloc_chrdev_region(&dev_id, minor, MEMDEV_NR_DEVS, "memdev");     //动态注册设备号
		if(ret < 0){
			printk("register devno error!\n");
			//return -EBUSY;
			return ret;
		}
		printk("dynamic2 register devno success!\n");
		major = MAJOR(dev_id);
		minor = MINOR(dev_id);
	}
	printk("successfully register an dev_id %x!\n", dev_id);
	printk("major[%d] minor[%d]\n", major, minor);

	//2.注册设备
	//初始化cdev结构
	cdev_init(&my_cdev, &rule_fops);
	my_cdev.owner = THIS_MODULE;	//指定模块的所属
	my_cdev.ops = &rule_fops;
	//添加cdev到内核
	ret = cdev_add(&my_cdev, dev_id, MEMDEV_NR_DEVS);
	if(ret < 0){
		printk("cdev_add error!\n");
		unregister_chrdev_region(dev_id, MEMDEV_NR_DEVS);
		//return -ENODEV;
		return ret;
	}
	printk("hello kernel, cdev_add success!\n");

	/* 为设备描述结构分配内存*/
  	mem_devp = kmalloc(MEMDEV_NR_DEVS * sizeof(struct mem_dev), GFP_KERNEL);//kmalloc函数返回的是虚拟地址(线性地址).
	if(!mem_devp){  //申请失败
		printk("mem_dev kmalloc error!\n");
		unregister_chrdev_region(dev_id, MEMDEV_NR_DEVS);
		return -ENOMEM;
	}
	memset(mem_devp, 0, sizeof(struct mem_dev));  //新申请的内存做初始化工作

	/*为设备分配内存*/
  	for(i = 0; i < MEMDEV_NR_DEVS; i++) {
        mem_devp[i].size = MEMDEV_SIZE;
        mem_devp[i].data = kmalloc(MEMDEV_SIZE, GFP_KERNEL);//分配内存给两个设备
        memset(mem_devp[i].data, 0, MEMDEV_SIZE);//初始化新分配到的内存
  	}
	return 0;
}

void dev_exit(void){
	//从内核中删除cdev
	cdev_del(&my_cdev);
	//注销设备号
	unregister_chrdev_region(dev_id, MEMDEV_NR_DEVS);
	printk("good bye kernel, dev exit ...\n");
}