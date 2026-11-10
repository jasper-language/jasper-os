#!/bin/sh
set -eu

exec taskset -c 4-11 /tmp/jasper-qemu-sw64-user/qemu-sw64 \
    -cpu core3 -L / "$@"
