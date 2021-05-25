obj-m += rootkit.o

all:
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
		rm -rf build
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

dev: all
	@bash install.sh

prod:
	@bash prod.sh
