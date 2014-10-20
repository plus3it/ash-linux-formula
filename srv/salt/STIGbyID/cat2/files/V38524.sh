#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38524
# Finding ID:	V-38524
# Version:	RHEL-06-000084
# Finding Level:	Medium
#
#     The system must not accept ICMPv4 redirect packets on any interface. 
#     Accepting ICMP redirects has few legitimate uses. It should be 
#     disabled unless it is absolutely required.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38524"
diag_out "  System must not accept ICMPv4"
diag_out "  redirect packets on any"
diag_out "  interface"
diag_out "----------------------------------"
