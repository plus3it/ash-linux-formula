#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38526
# Finding ID:	V-38526
# Version:	RHEL-06-000086
# Finding Level:	Medium
#
#     The system must not accept ICMPv4 secure redirect packets on any 
#     interface. Accepting "secure" ICMP redirects (from those gateways 
#     listed as default gateways) has few legitimate uses. It should be 
#     disabled unless it is absolutely required.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38526"
diag_out "  System must not accept ICMPv4"
diag_out "  secure redirect packets on any"
diag_out "  interface"
diag_out "----------------------------------"
