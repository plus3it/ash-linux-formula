#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38538
# Finding ID:	V-38538
# Version:	RHEL-06-000177
# Finding Level:	Low
#
#     The operating system must automatically audit account termination. In 
#     addition to auditing new user and group accounts, these watches will 
#     alert the system administrator(s) to any modifications. Any 
#     unexpected users, groups, or modifications should be investigated 
#     for legitimacy.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "-----------------------------------"
diag_out "STIG Finding ID: V-38538"
diag_out "  Operating system must"
diag_out "  automatically audit account"
diag_out "  termination"
diag_out "-----------------------------------"
