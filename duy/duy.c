#include <linux/syscalls.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/tty.h>
#include <linux/string.h>

int ksys_pnametoid(const char __user *name) {
    printk(KERN_INFO "Hello world!");
    return 0;
}

SYSCALL_DEFINE1(pnametoid, char __user *, name) {
    return ksys_pnametoid(name);
}

int ksys_pidtoname(int pid, char __user *buf, int len) {
    printk(KERN_INFO "Goodbye world!");
    return 0;
}

SYSCALL_DEFINE3(pidtoname, int, pid, char __user *, buf, int, len) {
    return ksys_pidtoname(pid, buf, len);
}
