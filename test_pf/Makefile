#General Purpose Makefile for Linux Kernel module by guoqingbo

#KERN_DIR = /usr/src/kernels/2.6.32-220.el6.x86_64/
#KERN_DIR = /usr/src/$(shell uname -r)
KERN_DIR = /lib/modules/$(shell uname -r)/build
test-objs := test_mod.o test_mod2.o
all:
	make -C $(KERN_DIR) M=$(shell pwd) modules   

clean:                                  
	make -C $(KERN_DIR) M=$(shell pwd) modules clean
	rm -rf modules.order

obj-m += test.o
