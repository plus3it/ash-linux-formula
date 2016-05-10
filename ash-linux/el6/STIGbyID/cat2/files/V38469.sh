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

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38469"
diag_out "  Ensure system binaries are not"
diag_out "  group- or world-writable"
diag_out "----------------------------------"

