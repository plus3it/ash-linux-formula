#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38643
# Finding ID:	V-38643
# Version:	RHEL-06-000282
# Finding Level:	Medium
#
#     There must be no world-writable files on the system. Data in 
#     world-writable files can be modified by any user on the system. In 
#     almost all circumstances, files can be configured using a combination 
#     of user and group permissions to support whatever ...
#
############################################################

CHECKDIR=${1:-UNDEF}

find ${CHECKDIR} -xdev -perm -002 -type f -exec printf \
  "Stripping global write-perms from: {}\n" \; -exec chmod o-w {} \;
