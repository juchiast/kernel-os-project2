#include <asm/unistd.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <asm/pgtable_types.h>
#include <linux/highmem.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/moduleparam.h>
#include <linux/kallsyms.h>
#include <asm/cacheflush.h>

MODULE_LICENSE("GPL");

static void **system_call_table_addr;

asmlinkage long (*origin_open)(const char __user *filename, int flags, umode_t mode);
asmlinkage long (*origin_write)(unsigned int fd, const char __user *buf, size_t count);

asmlinkage long my_open(const char __user *filename, int flags, umode_t mode) {
    printk(KERN_INFO "Hook open");
    return origin_open(filename, flags, mode);
}
asmlinkage long my_write(unsigned int fd, const char __user *buf, size_t count) {
    printk(KERN_INFO "Hook write");
    return origin_write(fd, buf, count);
}

static int make_rw(unsigned long address) {
    unsigned int level;
    pte_t *pte = lookup_address(address, &level);
    if(pte->pte &~_PAGE_RW){
        pte->pte |=_PAGE_RW;
    }
    return 0;
}

static int make_ro(unsigned long address) {
    unsigned int level;
    pte_t *pte = lookup_address(address, &level);
    pte->pte = pte->pte &~_PAGE_RW;
    return 0;
}

static int __init entry_point(void) {
    system_call_table_addr = (void **) kallsyms_lookup_name("sys_call_table");
    origin_open = system_call_table_addr[__NR_open];
    origin_write = system_call_table_addr[__NR_write];
    make_rw((unsigned long) system_call_table_addr);
    system_call_table_addr[__NR_open] = my_open;
    system_call_table_addr[__NR_write] = my_write;
    make_ro((unsigned long) system_call_table_addr);
    return 0;
}
static void __exit exit_point(void) {
    make_rw((unsigned long)system_call_table_addr);
    system_call_table_addr[__NR_open] = origin_open;
    system_call_table_addr[__NR_write] = origin_write;
    make_ro((unsigned long)system_call_table_addr);
}
module_init(entry_point);
module_exit(exit_point);
