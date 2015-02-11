#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38544
# Finding ID:	V-38544
# Version:	RHEL-06-000097
# Finding Level:	Medium
#
#     The system must use a reverse-path filter for IPv4 network traffic 
#     when possible by default. Enabling reverse path filtering drops 
#     packets with source addresses that should not have been able to be 
#     received on the interface they were received on. It should not be 
#     used on systems which are ...
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38544"
diag_out "  IPv4 reverse-path filtering must"
diag_out "  be enabled for all interfaces"
diag_out "----------------------------------"
