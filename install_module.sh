#!/bin/sh
set -x
# WARNING: this script doesn't check for errors, so you have to enhance it in case any of the commands
# below fail.

lsmod
rmmod submitjob_mod
insmod submitjob_mod.ko
lsmod
