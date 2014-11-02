#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38466
# Finding ID:	V-38466
# Version:	RHEL-06-000046
# Finding Level:	Medium
#
#     Library files must be owned by root. Files from shared library 
#     directories are loaded into the address space of processes (including 
#     privileged ones) or of the kernel itself at runtime. Proper ownership 
#     is necessary to protect the ...
#
#  CCI: CCI-001499
#  NIST SP 800-53 :: CM-5 (6)
#  NIST SP 800-53A :: CM-5 (6).1
#  NIST SP 800-53 Revision 4 :: CM-5 (6)
#
############################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38466"
diag_out "  Ensure standard, system-wide"
diag_out "  shared library files in: " 
diag_out "  * /lib"
diag_out "  * /lib64"
diag_out "  * /usr/lib"
diag_out "  * /usr/lib64"
diag_out "  are owned by the root user"
diag_out "----------------------------------"

