#include <unistd.h>
#include <sys/syscall.h>
#include <stdio.h>

#if defined(__x86_64__)
#define pnametoid 335
#define pidtoname 336
#elif defined(__i386__)
#define pnametoid 387
#define pidtoname 388
#else
#define pnametoid 294
#define pidtoname 295
#endif

int main() {
    printf("call pnametoid: %d\n", pnametoid);
    printf("%d\n", syscall(pnametoid, (char *)0));
    printf("call pidtoname: %d\n", pidtoname);
    printf("%d\n", syscall(pidtoname, (int)0, (char *)0, (int)0));
    return 0;
}
