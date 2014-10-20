#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38481
# Finding ID:	V-38481
# Version:	RHEL-06-000011
# Finding Level:	Medium
#
#     System security patches and updates must be installed and up-to-date. 
#     Installing software updates is a fundamental mitigation against the 
#     exploitation of publicly-known vulnerabilities.
#
############################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38481"
diag_out "  Ensure that system is connected"
diag_out "  to an update-server and that all"
diag_out "  managed-packages are up to date"
diag_out "----------------------------------"
