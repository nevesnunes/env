#include <linux/init.h>
#include <linux/module.h>
#include <linux/sched.h>

/**
 * Running:
 * ```sh
 * # Build
 * make -C /lib/modules/$(uname -r)/build M=$PWD modules
 * # Test
 * insmod foo_module.ko
 * # Validation
 * dmesg
 * # Teardown
 * rmmod foo_module.ko
 * ```
 *
 * References:
 * - https://gist.github.com/17twenty/6313566
 * - https://kernelnewbies.org/FAQ/LinuxKernelModuleCompile
 * - https://www.kernel.org/doc/html/latest/kbuild/modules.html
 */

int foo_init() {
    printk("foo init.\n");
    return 0;
}

void foo_exit() { printk("foo exit.\n"); }

module_init(foo_init);
module_exit(foo_exit);

MODULE_LICENSE("GPL");
