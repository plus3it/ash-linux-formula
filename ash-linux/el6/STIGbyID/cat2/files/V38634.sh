#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38634
# Finding ID:	V-38634
# Version:	RHEL-06-000161
# Finding Level:	Medium
#
#     Automatically rotating logs (by setting this to "rotate") minimizes 
#     the chances of the system unexpectedly running out of disk space by 
#     being overwhelmed with log data. However, for systems that must never 
#     discard log data, or which use external processes to transfer it and 
#     reclaim space, "keep_logs" can be employed. 
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38634"
diag_out "  system must rotate audit log"
diag_out "  files that reach the maximum"
diag_out "  file size"
diag_out "----------------------------------"
