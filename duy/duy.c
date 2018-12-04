#include <linux/syscalls.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

static int len(const char __user *s) {
    const char __user *ss = s;
    char c;
    if (ss == NULL) return 0;
    do {
        get_user(c, ss++);
    } while (c != '\0');
    return (ss - s) - 1;
}

static char *from_user(const char __user *s) {
    int l;
    char *ret;
    if (s == NULL) return NULL;
    l = len(s);
    ret = kmalloc(l + 1, GFP_KERNEL);
    if (ret == NULL) return NULL;
    if (copy_from_user(ret, s, l) != 0) {
        kfree(ret);
        return NULL;
    }
    ret[l] = '\0';
    return ret;
}

int ksys_pnametoid(const char __user *_name) {
    struct task_struct *task;
    int ret;
    const char *name;
    name = from_user(_name);
    if (name == NULL) return -1;
    ret = -1;
    for_each_process(task) {
        if(strcmp(task->comm, name) == 0){
            ret = task_pid_nr(task);
            break;
        }
    }
    kfree(name);
    return ret;
}

SYSCALL_DEFINE1(pnametoid, char __user *, name) {
    return ksys_pnametoid(name);
}

static int to_user(const char *s, char __user *buf, int len) {
    int slen = strlen(s);
    if (slen > len - 1) return 0;
    if (copy_to_user(buf, s, slen + 1) != 0) {
        return -1;
    }
    return slen;
}

int ksys_pidtoname(int pid, char __user *buf, int len) {
    struct task_struct *task;
    for_each_process(task) {
        if (task_pid_nr(task) == pid) {
            return to_user(task->comm, buf, len);
        }
    }
    return -1;
}

SYSCALL_DEFINE3(pidtoname, int, pid, char __user *, buf, int, len) {
    return ksys_pidtoname(pid, buf, len);
}
