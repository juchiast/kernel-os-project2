#include <asm/unistd.h>
#include <asm/cacheflush.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <asm/pgtable_types.h>
#include <linux/highmem.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/moduleparam.h>
#include <linux/unistd.h>
#include <asm/cacheflush.h>

MODULE_LICENSE("GPL");

void **system_call_table_addr;

asmlinkage int (*custom_syscall) (const char __user *name);

asmlinkage int captain_hook(const char __user *play_here) {
    printk(KERN_INFO "Pname Syscall:HOOK! HOOK! HOOK! HOOK!...ROOOFFIIOO!");
    return custom_syscall(play_here);
}

int make_rw(unsigned long address){
    unsigned int level;
    pte_t *pte = lookup_address(address, &level);
    if(pte->pte &~_PAGE_RW){
        pte->pte |=_PAGE_RW;
    }
    return 0;
}

int make_ro(unsigned long address){
    unsigned int level;
    pte_t *pte = lookup_address(address, &level);
    pte->pte = pte->pte &~_PAGE_RW;
    return 0;
}
static int __init entry_point(void){
    printk(KERN_INFO "Captain Hook loaded successfully..\n");
    system_call_table_addr = (void*)0xffffffff81601680;
    custom_syscall = system_call_table_addr[__NR_pnametoid];
    make_rw((unsigned long)system_call_table_addr);
    system_call_table_addr[__NR_pnametoid] = captain_hook;
    return 0;
}
static void __exit exit_point(void){
        printk(KERN_INFO "Unloaded Captain Hook successfully\n");
    /*Restore original system call */
    system_call_table_addr[__NR_pnametoid] = custom_syscall;
    /*Renable page protection*/
    make_ro((unsigned long)system_call_table_addr);
}
module_init(entry_point);
module_exit(exit_point);
