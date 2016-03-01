#include "chardev.h"

MODULE_LICENSE("GPL");

unsigned int major = 254;
unsigned int minor = 0;
dev_t dev_id;
struct cdev my_cdev;
struct mem_dev *mem_devp;  //设备结构体指针
int mutex = 1;
int counter = 0;

struct file_operations rule_fops = {
	.owner = THIS_MODULE,
	.llseek = my_llseek,
	.open = my_open,
	.read = my_read,
	.write = my_write,
	.release = my_release,
};

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
	printk("<kernel>read content is [%s]\n", buf);
	return count;
}

ssize_t my_write(struct file *file, const char __user *buf, size_t size, loff_t *ppos){
	//printk("memdev write success!\n");
	//char kbuf[20];
	//memcpy(kbuf, buf, size);
	unsigned int p = *ppos;
	unsigned int count = size;
	struct mem_dev *dev = file->private_data;  //获得设备结构体指针

	if(p >= MEMDEV_SIZE)
		return 0;
	if(count > MEMDEV_SIZE - p)
		count = MEMDEV_SIZE - p;

	//从用户空间写入数据
	if(copy_from_user(dev->data + p, buf, count)){
		return -EFAULT;
	}
	*ppos += count;
	printk(KERN_INFO"written %d byte(s) from %d\n", count, p);
	printk("<kernel>written content is [%s]\n", buf);
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
			printk("dynamic register devno success!\n");
			major = MAJOR(dev_id);
			minor = MINOR(dev_id);
		}
		else{
			printk("static register devno success!\n");
		}
	}
	//否则由内核动态分配
	else{
		ret = alloc_chrdev_region(&dev_id, minor, 1, "memdev");     //动态注册设备号
		if(ret < 0){
			printk("register devno error!\n");
			//return -EBUSY;
			return ret;
		}
		printk("dynamic register devno success!\n");
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