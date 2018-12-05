#include <linux/syscalls.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/pid.h>

int ksys_pnametoid(const char __user *_name) {
    char *name;
    struct task_struct *task;
    int ret;

    name = kmalloc(256, GFP_KERNEL);
    if (name == NULL) return -1;
    if (strncpy_from_user(name, _name, 256) < 0) {
        kfree(name);
        return -1;
    }

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
    struct pid* p;
    struct task_struct *task;
    p = find_get_pid(pid);
    if (p == NULL) return -1;
    task = get_pid_task(p, PIDTYPE_PID);
    if (task == NULL) return -1;
    return to_user(task->comm, buf, len);
}

SYSCALL_DEFINE3(pidtoname, int, pid, char __user *, buf, int, len) {
    return ksys_pidtoname(pid, buf, len);
}
