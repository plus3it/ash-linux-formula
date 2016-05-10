#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38602
# Finding ID:	V-38602
# Version:	RHEL-06-000218
# Finding Level:	High
#
#     The rlogind service must not be running. The rlogin service uses 
#     unencrypted network communications, which means that data from the 
#     login session, including passwords and all other information 
#     transmitted during the session, can be stolen ...
#
############################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38602"
diag_out "  The rlogind service must not be"
diag_out "  running"
diag_out "----------------------------------"

