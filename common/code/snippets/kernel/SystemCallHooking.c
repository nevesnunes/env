#include <linux/module.h>
#include <linux/printk.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <asm/unistd.h>
#include <asm/pgtable_types.h>
#include <linux/highmem.h>

#include "hook_function_ptr.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("MicroMike");
MODULE_DESCRIPTION("Hello World Module");


/* sys_call_table address */
unsigned long *sys_call_table = SYS_CALL_TABLE_ADDR;


/* 
 * user function pointer for some linux kernel function call 
 * since some of the function didn't export to the module.
 */
int (*real_do_execve)(const char *, 
		const char __user *const __user *, 
		const char __user *const __user *) = DO_EXECVE_ADDR;

int (*real_do_execve_common)(const char *,
			struct user_arg_ptr argv,
			struct user_arg_ptr envp) = DO_EXECVE_COMMON_ADDR;

void (*real_putname)(struct filename *name) = PUTNAME_ADDR;

/* real_execve address */
asmlinkage int (*real_execve)(const char __user *, 
			const char __user *const __user *, 
			const char __user *const __user *);

/* 
 * custom do_execve for firefox process.
 * which will insert two new arguments which is our usermode monitor program,
 * append the rest of the arguments as the new argument for the usermdoe monitor.
 */
int custom_do_execve(const char __user *filename,
		const char __user *const __user *__argv,
		const char __user *const __user *__envp)
{
	/* 
         * log some information you want .... 
         * ...
 	 * ...
	 */

	result = real_do_execve_common(filename, __argv, __envp);
	return result;
	
}
/* hook sys_execve which is */
asmlinkage int custom_execve(const char __user *filename, const char __user *const __user *argv, const char __user *const __user *envp)
{
	/* if the current process is firefox, hook it  */
	if( strstr(current->comm, "firefox")) {
		struct filename *path = getname(filename);
		int error = PTR_ERR(path);
		if (!IS_ERR(path)) {
			error = custom_do_execve(path->name, argv, envp);
			real_putname(path);
		}
		return error;
	}

	return real_execve(filename, argv, envp);
}

int make_rw(unsigned long address) 
{
	unsigned int level;
	pte_t *pte = lookup_address(address, &level);
	if(pte->pte &~ _PAGE_RW)
		pte->pte |= _PAGE_RW;
	return 0;
}


int make_ro(unsigned long address)
{
	unsigned int level;
	pte_t *pte = lookup_address(address, &level);
	pte->pte = pte->pte & ~_PAGE_RW;
	return 0;
}


static int __init test_init(void) 
{
	/* hook execve system call*/
	make_rw((unsigned long)sys_call_table);
	real_execve = (int (*)(const char __user *, 
			       const char __user *const __user *, 
			       const char __user *const __user *))
	*(sys_call_table + __NR_execve);
	*(sys_call_table + __NR_execve) = (unsigned long)custom_execve;
	make_ro((unsigned long)sys_call_table);

	return 0;
}

static void __exit test_exit(void)
{
	/* resume what it should be */
	make_rw((unsigned long)sys_call_table);
	*(sys_call_table + __NR_execve) = (unsigned long)real_execve;
	make_ro((unsigned long)sys_call_table);
}


module_init(test_init);
module_exit(test_exit);