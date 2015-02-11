#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38613
# Finding ID:	V-38613
# Version:	RHEL-06-000237
# Finding Level:	Medium
#
#     The system must not permit root logins using remote access programs 
#     such as ssh. Permitting direct root login reduces auditable 
#     information about who ran privileged commands on the system and also 
#     allows direct attack attempts on root's password.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38613"
diag_out "  The must not allow network-based"
diag_out "  root logins"
diag_out "----------------------------------"
