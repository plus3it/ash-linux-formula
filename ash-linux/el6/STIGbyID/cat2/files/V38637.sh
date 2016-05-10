#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38637
# Finding ID:	V-38637
# Version:	RHEL-06-000281
# Finding Level:	Medium
#
#     The system package management tool must verify contents of all files 
#     associated with the audit package. The hash on important files like 
#     audit system executables should match the information given by the 
#     RPM database. Audit executables with erroneous hashes could be a sign 
#     of nefarious activity on the ...
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38637"
diag_out "  system must retain enough"
diag_out "  rotated audit logs to cover the"
diag_out "  required log retention period"
diag_out "----------------------------------"
