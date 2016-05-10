#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38477
# Finding ID:	V-38477
# Version:	RHEL-06-000051
# Finding Level:	Medium
#
#     Users must not be able to change passwords more than once every 24 
#     hours. Setting the minimum password age protects against users 
#     cycling back to a favorite password after satisfying the password 
#     reuse requirement.
#
############################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38477"
diag_out "  Set minimum password change-"
diag_out "  frequency to 24 hours"
diag_out "----------------------------------"
