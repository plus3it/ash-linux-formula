#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38472
# Finding ID:	V-38472
# Version:	RHEL-06-000048
# Finding Level:	Medium
#
#     All system command files must be owned by root. System binaries are 
#     executed by privileged users as well as system services, and 
#     restrictive permissions are necessary to ensure that their execution 
#     of these programs cannot be co-opted.
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
diag_out "STIG Finding ID: V-38472"
diag_out "  Ensure that all system binaries"
diag_out "  executables in:"
diag_out "  * /bin"
diag_out "  * /usr/bin"
diag_out "  * /usr/local/bin"
diag_out "  * /sbin"
diag_out "  * /usr/sbin"
diag_out "  * /usr/local/sbin"
diag_out "  Are owned by the root user"
diag_out "----------------------------------"
