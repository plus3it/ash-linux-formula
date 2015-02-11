#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38636
# Finding ID:	V-38636
# Version:	RHEL-06-000159
# Finding Level:	Medium
#
#     The system must retain enough rotated audit logs to cover the 
#     required log retention period. The total storage for audit log files 
#     must be large enough to retain log information over the period 
#     required. This is a function of the maximum log file size and the 
#     number of logs retained.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38636"
diag_out "  system must retain enough"
diag_out "  rotated audit logs to cover the"
diag_out "  required log retention period"
diag_out "----------------------------------"
