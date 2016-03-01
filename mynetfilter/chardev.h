#ifndef __CHARDEV_H__
#define __CHARDEV_H__

#include <linux/module.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/cdev.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <asm/uaccess.h>

#define MEMDEV_SIZE 4096
#define MEMDEV_NR_DEVS 2

struct mem_dev{
	char *data;         //分配到内存的起始地址
	unsigned long size; //内存的大小
};

int my_open(struct inode *inode, struct file *file);
int my_release(struct inode *inode, struct file *file);
loff_t my_llseek(struct file *file, loff_t offset, int whence);
ssize_t my_read(struct file *file, char __user *buf, size_t size, loff_t *ppos);
ssize_t my_write(struct file *file, const char __user *buf, size_t size, loff_t *ppos);
int dev_init(void);
void dev_exit(void);

#endif