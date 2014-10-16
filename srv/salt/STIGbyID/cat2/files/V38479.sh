#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38479
# Finding ID:	V-38479
# Version:	RHEL-06-000053
# Finding Level:	Medium
#
#     User passwords must be changed at least every 60 days. Setting the 
#     password maximum age ensures users are required to periodically 
#     change their passwords. This could possibly decrease the utility of a 
#     stolen password. Requiring shorter password lifetimes ...
#
############################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "  Set local users' maximum"
diag_out "  password-age to sixty days"
diag_out "----------------------------------"
