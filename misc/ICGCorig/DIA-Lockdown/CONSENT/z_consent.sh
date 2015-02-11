#!/bin/sh

if [ "$PS1" ]
then
/usr/sbin/consent.sh || exit 1
fi
