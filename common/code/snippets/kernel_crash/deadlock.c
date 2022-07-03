/*
Here we launch 2 kernel threads and try to take the 2 semaphores:

In thread "one" the semaphores are taken in the order  sync1 --> sync2. Also they are released like sync2 --> sync1
       down(&sync1);
       cpu1 = get_cpu();
  ...
  ...
       down(&sync2);
       up(&sync2);
       up(&sync1);

In thread 2 we take the semaphores in opposite order  sync2 --> sync1. Also they are released like sync1 --> sync2
        down(&sync2);
        cpu2 = get_cpu();
  ...
  ...
        down(&sync1);
        up(&sync1);
        up(&sync2);

If we launch this program we see that these 2 threads gets entangled in a deadlock. This is a classic case of ABBA deadlock.
(The solution for this is correct lock ordering)

The print from the dmseg shows following :

Dec 12 02:49:25 localhost kernel: device-mapper: multipath: kundan message: error getting device 8:0
Dec 12 02:49:25 localhost kernel: threads: module verification failed: signature and/or required key missing - tainting kernel
Dec 12 02:49:25 localhost kernel: module_init address of sync1 = ffffffffa0536280 sync2 = ffffffffa0536260
Dec 12 02:49:25 localhost kernel: main thread cpu = 1
Dec 12 02:49:25 localhost kernel: IN THREAD FUNCTION 1
Dec 12 02:49:25 localhost kernel: t1 cpu = 1 shared_var = 0
Dec 12 02:49:25 localhost kernel: IN THREAD FUNCTION 2
Dec 12 02:49:25 localhost kernel: t2 cpu = 3 shared_var = 0

Also  ps command shows 2 kernel thread in UNINTERRUPTIBLE SLEEP :
ps :
   3580      2   1  ffff88007b1aa220  UN   0.0       0      0  [one]
   3581      2   3  ffff88007b1ac440  UN   0.0       0      0  [two]

- http://sklinuxblog.blogspot.com/2018/06/linux-kernel-crash-dump-analysis.html
*/

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/semaphore.h>
#include <linux/version.h>

#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/slab.h>

struct semaphore sync1;
struct semaphore sync2;
struct task_struct *task1;
struct task_struct *task2;
int shared_var;
int data;

int thread_function_one(void *data) {
    int ret = 10;
    int cpu1;
    printk(KERN_INFO "IN THREAD FUNCTION 1 \n");

    while (!kthread_should_stop()) {
        down(&sync1);
        cpu1 = get_cpu();
        put_cpu();
        printk("t1 cpu = %d shared_var = %d\n", cpu1, shared_var);
        msleep(1000);
        down(&sync2);
        up(&sync2);
        up(&sync1);
    }
    printk(KERN_INFO "EXIT from thread function 1\n");
    return ret;
}

int thread_function_two(void *data) {
    int ret = 10;
    int cpu2;
    printk(KERN_INFO "IN THREAD FUNCTION 2 \n");

    while (!kthread_should_stop()) {
        down(&sync2);
        cpu2 = get_cpu();
        put_cpu();
        printk("t2 cpu = %d shared_var = %d\n", cpu2, shared_var);
        msleep(2000);
        down(&sync1);
        up(&sync1);
        up(&sync2);
    }
    printk(KERN_INFO "EXIT from thread function 2\n");
    return ret;
}

static int kernel_init(void) {
    int cpu3;
    sema_init(&sync1, 1);
    sema_init(&sync2, 1);
    printk(KERN_INFO "module_init address of sync1 = %p sync2 = %p\n",
           &sync1,
           &sync2);

    cpu3 = get_cpu();
    put_cpu();
    printk("main thread cpu = %d \n", cpu3);

    shared_var = 0;
    task1 = kthread_create(&thread_function_one, (void *)&data, "one");
    kthread_bind(task1, cpu3);
    wake_up_process(task1);

    cpu3 = 3;
    task2 = kthread_create(&thread_function_two, (void *)&data, "two");
    kthread_bind(task2, cpu3);
    wake_up_process(task2);

    return 0;
}

static void kernel_exit(void) {
    kthread_stop(task1);
    kthread_stop(task2);
    printk(KERN_INFO "module_exit\n");
}

module_init(kernel_init);
module_exit(kernel_exit);

MODULE_AUTHOR("K_K");
MODULE_DESCRIPTION("SIMPLE MODULE");
MODULE_LICENSE("GPL");
