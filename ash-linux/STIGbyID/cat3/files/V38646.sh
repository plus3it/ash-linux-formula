#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38646
# Finding ID:	V-38646
# Version:	RHEL-06-000266
# Finding Level:	Low
#
#     The oddjobd service must not be running. The "oddjobd" service may 
#     provide necessary functionality in some environments but it can be 
#     disabled if it is not needed. Execution of tasks by privileged 
#     programs, on behalf of unprivileged ones, has traditionally been a 
#     source of privilege escalation security issues. 
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38646"
diag_out "  The oddjobd service must not be"
diag_out "  running."
diag_out "----------------------------------"
