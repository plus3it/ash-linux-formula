#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38579
# Finding ID:	V-38579
# Version:	RHEL-06-000065
# Finding Level:	Medium
#
#     The system boot loader configuration file(s) must be owned by root. 
#     Only root should be able to modify important boot parameters.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38579"
diag_out "  The bootloader configuration"
diag_out "  files must be owned by the root"
diag_out "  user"
diag_out "----------------------------------"
