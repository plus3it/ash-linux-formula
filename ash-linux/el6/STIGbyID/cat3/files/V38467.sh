#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38467
# Finding ID:	V-38467
# Version:	RHEL-06-000004
# Finding Level:	Low
#
#     The system must use a separate file system for the system audit data 
#     path. Placing "/var/log/audit" in its own partition enables better 
#     separation between audit files and other files, and helps ensure that 
#     auditing cannot be halted due to the partition running out of space.
#
#  CCI: CCI-000137
#  NIST SP 800-53 :: AU-4
#  NIST SP 800-53A :: AU-4.1 (i)
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38467"
diag_out "  The /var/log/audit directory"
diag_out "  should be  on its own device"
diag_out "----------------------------------"
