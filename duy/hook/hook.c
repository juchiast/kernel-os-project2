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
#include <linux/slab.h>
#include <linux/fdtable.h>

MODULE_LICENSE("GPL");

static void **system_call_table_addr;

static char* pidtoname(int pid) {
    struct pid* p;
    struct task_struct *task;
    p = find_get_pid(pid);
    if (p == NULL) return NULL;
    task = get_pid_task(p, PIDTYPE_PID);
    if (task == NULL) return NULL;
    return task->comm;
}

static char *get_path(struct files_struct *files, unsigned int fd) {
    char *pathname, *ret, *tmp;
    struct file *file;
    struct path *path;
    spin_lock(&files->file_lock);
    file = fcheck_files(files, fd);
    if (!file) {
        spin_unlock(&files->file_lock);
        return NULL;
    }
    path = &file->f_path;
    path_get(path);
    spin_unlock(&files->file_lock);
    pathname = kmalloc(1024, GFP_KERNEL);
    if (!pathname) {
        path_put(path);
        return NULL;
    }
    ret = d_path(path, pathname, 1024);
    path_put(path);
    if (IS_ERR(ret)) {
        kfree(pathname);
        return NULL;
    }
    tmp = kmalloc(1024, GFP_KERNEL);
    if (tmp == NULL) {
        kfree(pathname);
        return NULL;
    }
    strncpy(tmp, ret, 1024);
    kfree(pathname);
    return tmp;
}

static asmlinkage long (*origin_open)(struct pt_regs *regs);
static asmlinkage long (*origin_write)(struct pt_regs *regs);

static asmlinkage long my_open(struct pt_regs *regs) {
    const char __user *fname = (const char __user *)regs->di;
    long ret = origin_open(regs);
    char *name = pidtoname(task_pid_nr(current));
    if (strcmp(name, "dmesg") != 0) {
        char *kfname = kmalloc(1024, GFP_KERNEL);
        strncpy(kfname, fname, 1024);
        printk(KERN_INFO "process %s open %s", name, kfname);
    }
    return ret;
}
static asmlinkage long my_write(struct pt_regs *regs) {
    unsigned int fd = (unsigned int)regs->di;
    size_t count = (size_t)regs->dx;
    long ret = origin_write(regs);
    char *name = pidtoname(task_pid_nr(current));
    if (strcmp(name, "dmesg") != 0) {
        char *path = get_path(current->files, fd);
        if (path != NULL) {
            printk(KERN_INFO "process %s write %lu bytes to %s", name, count, path);
            kfree(path);
        } else {
            printk(KERN_INFO "process %s write %lu bytes to %u", name, count, fd);
        }
    }
    return ret;
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
    make_rw((unsigned long) system_call_table_addr);
    system_call_table_addr[__NR_open] = origin_open;
    system_call_table_addr[__NR_write] = origin_write;
    make_ro((unsigned long) system_call_table_addr);
}
module_init(entry_point);
module_exit(exit_point);
