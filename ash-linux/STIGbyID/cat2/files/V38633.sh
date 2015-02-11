#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38633
# Finding ID:	V-38633
# Version:	RHEL-06-000160
# Finding Level:	Medium
#
#     The system must set a maximum audit log file size. The total storage 
#     for audit log files must be large enough to retain log information 
#     over the period required. This is a function of the maximum log file 
#     size and the number of logs retained.
#
############################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38633"
diag_out "  The system must set a maximum"
diag_out "  audit log file-size. The minimum"
diag_out "  recommended value is '6'"
diag_out "----------------------------------"
