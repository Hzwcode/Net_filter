My_netfilter

Lightweight Firewall, course design of Computer Network

HOW TO create /dev/memdev automatically

In order to make it automatically, instead of running sudo mknod /dev/memdev -m 0666 c 248 0, need to create dev class according to the newly added codes, and add a special file in the file system.

Steps:

use class_create() to create a device class.
use device_create() to create a device instance of the class.
create a udev rule file in /etc/udev/rules.d/ or /usr/lib/udev/rules.d/ (in my case which is the latter one), and the content is as follow.
$ cat 09-mydev.rules
KERNEL=="memdev", MODE="0666"
Then, every time when run sudo insmod [MODNAME], the device file will be automatically created as /dev/memdev, with the permission 0666.

Note

This lightweight firewall is a linux kernel module, based on linux ubuntu-14.04 LTS linux-headers.
The ui is based on linux gtk+-2.0.

Further information is in the Makefile.