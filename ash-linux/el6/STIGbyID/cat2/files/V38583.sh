#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38583
# Finding ID:	V-38583
# Version:	RHEL-06-000067
# Finding Level:	Medium
#
#     The system boot loader configuration file(s) must have mode 0600 or 
#     less permissive. Proper permissions ensure that only the root user 
#     can modify important boot parameters.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38583"
diag_out "  System boot-loader configuration"
diag_out "  files must be mode 0600 or less"
diag_out "  permissive"
diag_out "----------------------------------"
