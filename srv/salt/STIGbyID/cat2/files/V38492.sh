#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38492
# Finding ID:	V-38492
# Version:	RHEL-06-000027
# Finding Level:	Medium
#
#     The system must prevent the root account from logging in from virtual 
#     consoles. Preventing direct root login to virtual console devices 
#     helps ensure accountability for actions taken on the system using the 
#     root account.
#
############################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38492"
diag_out "  Prevent the root user from"
diag_out "  logging in vi virtual consoles"
diag_out "----------------------------------"
