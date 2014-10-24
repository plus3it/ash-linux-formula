#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38658
# Finding ID:	V-38658
# Version:	RHEL-06-000274
# Finding Level:	Medium
#
#     The system must prohibit the reuse of passwords within twenty-four 
#     iterations. Preventing reuse of previous passwords helps ensure that 
#     a compromised password is not reused by a user.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38658"
diag_out "  System must prohibit the reuse"
diag_out "  of passwords within twenty-four"
diag_out "  iterations"
diag_out "----------------------------------"

