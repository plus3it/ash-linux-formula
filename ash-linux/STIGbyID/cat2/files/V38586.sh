#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38586
# Finding ID:	V-38586
# Version:	RHEL-06-000069
# Finding Level:	Medium
#
#     The system must require authentication upon booting into single-user 
#     and maintenance modes. This prevents attackers with physical access 
#     from trivially bypassing security on the machine and gaining root 
#     access. Such accesses are further prevented by configuring the 
#     bootloader password.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38586"
diag_out "  Authentication must be required"
diag_out "  for access to host while in"
diag_out "  single-user mode"
diag_out "----------------------------------"
