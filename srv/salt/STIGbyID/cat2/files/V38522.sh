#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38522
# Finding ID:	V-38522
# Version:	RHEL-06-000167
# Finding Level:	Medium
#
#     Arbitrary changes to the system time can be used to obfuscate 
#     nefarious activities in log files, as well as to confuse network 
#     services that are highly dependent upon an accurate system time (such 
#     as sshd). All changes to the system time should be audited. 
#
############################################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38522"
diag_out "  Audit subsystem must be set to"
diag_out "  audit calls to the settimeofday"
diag_out "  system call"
diag_out "----------------------------------"
