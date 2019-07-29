#include <linux/kernel.h>
#include <linux/module.h>

int init_module(void) {
    pr_info("Hello world\n");
    //printk(KERN_INFO "Hello world\n");
    return 0;
}

void cleanup_module(void) { printk(KERN_INFO "Goodbye world\n"); }
