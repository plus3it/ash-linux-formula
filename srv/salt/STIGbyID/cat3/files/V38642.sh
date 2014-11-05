#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38642
# Finding ID:	V-38642
# Version:	RHEL-06-000346
# Finding Level:	Low
#
#     The system default umask for daemons must be 027 or 022. The umask 
#     influences the permissions assigned to files created by a process at 
#     run time. An unnecessarily permissive umask could result in files 
#     being created with insecure permissions.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38642"
diag_out "  The system default umask for"
diag_out "  daemons must be 027 or 022."
diag_out "----------------------------------"
