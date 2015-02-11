#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38592
# Finding ID:	V-38592
# Version:	RHEL-06-000356
# Finding Level:	Medium
#
#     The system must require administrator action to unlock an account 
#     locked by excessive failed login attempts. Locking out user accounts 
#     after a number of incorrect attempts prevents direct password 
#     guessing attacks. Ensuring that an administrator is involved in 
#     unlocking locked accounts draws appropriate ...
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38592"
diag_out "  User accounts must be locked if"
diag_out "  three consecutive authentication"
diag_out "  failures occur"
diag_out "----------------------------------"
