#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38469
# Finding ID:	V-38469
# Version:	RHEL-06-000047
# Finding Level:	Medium
#
#     All system command files must have mode 0755 or less permissive. 
#     System binaries are executed by privileged users, as well as system 
#     services, and restrictive permissions are necessary to ensure 
#     execution of these programs cannot be co-opted.
#
############################################################

CHECKDIR=${1:-UNDEF}

find -L ${CHECKDIR} -perm /022 -type f -exec printf \
  "Stripping write-perms from: {}\n" \; -exec chmod go-w {} \;
