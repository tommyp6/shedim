obj-m += rootkit.o
rootkit-objs +=

all:
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

dev: all
	@bash install.sh
