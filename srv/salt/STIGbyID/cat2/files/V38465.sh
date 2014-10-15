#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38465
# Finding ID:	V-38465
# Version:	RHEL-06-000045
# Finding Level:	Medium
#
#     Library files must have mode 0755 or less permissive. Files from 
#     shared library directories are loaded into the address space of 
#     processes (including privileged ones) or of the kernel itself at 
#     runtime. Restrictive permissions are necessary to protect ...
#
############################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38465"
diag_out "  Ensure standard, system-wide"
diag_out "  shared library files in: " 
diag_out "  * /lib"
diag_out "  * /lib64"
diag_out "  * /usr/lib"
diag_out "  * /usr/lib64"
diag_out "  are not set to a world- or"
diag_out "  group-writable state"
diag_out "----------------------------------"

