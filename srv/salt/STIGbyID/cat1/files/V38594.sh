#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38594
# Finding ID:	V-38594
# Version:	RHEL-06-000214
# Finding Level:	High
#
#     The rshd service must not be running. The rsh service uses 
#     unencrypted network communications, which means that data from the 
#     login session, including passwords and all other information 
#     transmitted during the session, can be stolen by ...
#
############################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38594"
diag_out "  The rsh-services must not be"
diag_out "  running"
diag_out "----------------------------------"

