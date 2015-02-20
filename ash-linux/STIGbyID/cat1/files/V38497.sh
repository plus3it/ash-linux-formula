#!/bin/sh
# 
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38497
# Finding ID: V-38497
# Version: RHEL-06-000030
#
#     If an account has an empty password, anyone could log in and run 
#     commands with the privileges of that account. Accounts with empty 
#     passwords should never be used in operational environments
#
#     If an account is configured for password authentication but does not 
#     have an assigned password, it may be possible to log into the account 
#     without authentication. Remove any instances of the "nullok" option 
#     in PAM subsystem
#
##########################################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38497"
diag_out "  Ensure null passwords are not"
diag_out "  usable for logins"
diag_out "----------------------------------"

