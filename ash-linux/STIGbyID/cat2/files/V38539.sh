#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38539
# Finding ID:	V-38539
# Version:	RHEL-06-000095
# Finding Level:	Medium
#
#     The system must be configured to use TCP syncookies. A TCP SYN flood 
#     attack can cause a denial of service by filling a system's TCP 
#     connection table with connections in the SYN_RCVD state. Syncookies 
#     can be used to track a connection when a subsequent ...
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38539"
diag_out "  System must be configured to use"
diag_out "  TCP syn-cookies to help prevent"
diag_out "  DoS via syn-flood attacks"
diag_out "----------------------------------"
