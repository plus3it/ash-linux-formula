#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38445
# Finding ID:	V-38445
# Version:	RHEL-06-000522
# Finding Level:	Medium
#
#     Audit log files must be group-owned by root. If non-privileged users 
#     can write to audit logs, audit trails can be modified or destroyed.
#
############################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38445"
diag_out "  All audit log files must be "
diag_out "  group-owned by root"
diag_out "----------------------------------"
