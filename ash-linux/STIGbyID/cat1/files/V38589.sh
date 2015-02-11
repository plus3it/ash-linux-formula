#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38589
# Finding ID:	V-38589
# Version:	RHEL-06-000211
# Finding Level:	High
#
#     The telnet daemon must not be running. The telnet protocol uses 
#     unencrypted network communication, which means that data from the 
#     login session, including passwords and all other information 
#     transmitted during the session, can be stolen ...
#
############################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38589"
diag_out "  Ensure telnet daemon is not"
diag_out "  enabled"
diag_out "----------------------------------"

