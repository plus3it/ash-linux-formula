#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38580
# Finding ID:	V-38580
# Version:	RHEL-06-000202
# Finding Level:	Medium
#
#     The audit system must be configured to audit the loading and 
#     unloading of dynamic kernel modules. The addition/removal of kernel 
#     modules can be used to alter the behavior of the kernel and 
#     potentially introduce malicious code into kernel space. It is 
#     important to have an audit trail of modules ...
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38580"
diag_out "  Configure the audit system to"
diag_out "  track kernel module insertions"
diag_out "  and deletions"
diag_out "----------------------------------"
