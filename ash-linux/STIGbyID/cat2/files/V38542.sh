#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38542
# Finding ID:	V-38542
# Version:	RHEL-06-000096
# Finding Level:	Medium
#
#     The system must use a reverse-path filter for IPv4 network traffic 
#     when possible on all interfaces. Enabling reverse path filtering 
#     drops packets with source addresses that should not have been able to 
#     be received on the interface they were received on. It should not be 
#     used on systems which are ...
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38542"
diag_out "  IPv4 reverse-path filtering must"
diag_out "  be enabled for all interfaces"
diag_out "----------------------------------"
