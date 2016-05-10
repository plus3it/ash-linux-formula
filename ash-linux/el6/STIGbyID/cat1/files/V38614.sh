#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38614
# Finding ID:	V-38614
# Version:	RHEL-06-000239
# Finding Level:	High
#
#     The SSH daemon must not allow authentication using an empty password. 
#     Configuring this setting for the SSH daemon provides additional 
#     assurance that remote login via SSH will require a password, even in 
#     the event of misconfiguration elsewhere.
#
############################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38614"
diag_out "  The SSH daemon must not allow "
diag_out "  use of empty passwords"
diag_out "----------------------------------"

