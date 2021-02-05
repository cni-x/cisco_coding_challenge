#!/bin/sh

[ "$USER" = root ] || { echo "You must run $0 as root."; exit 1; }

[ -d root ] || mkdir root
[ -d root/ip ] || mkdir root/ip
[ -f root/ip/127.0.0.1 ] || touch root/ip/127.0.0.1
[ -d root/servers ] || mkdir root/servers
[ -f root/servers/@ ] || cp dnsroots.global root/servers/@

export ROOT=./root
export IP=127.0.0.1
export IPSEND=0.0.0.0
export CACHESIZE=1024576
export GID=0

# UID is read-only in bash, so we set it with env.
#
# Dnscache requires 128 bytes from standard input to start up; we use
# the dnscache binary itself for that.
exec env UID=0 ./dnscache <dnscache

