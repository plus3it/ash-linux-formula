#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38598
# Finding ID:	V-38598
# Version:	RHEL-06-000216
# Finding Level:	High
#
#     The rexecd service must not be running. The rexec service uses 
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
diag_out "STIG Finding ID: V-38598"
diag_out "  The rexec service must not be"
diag_out "  running"
diag_out "----------------------------------"

