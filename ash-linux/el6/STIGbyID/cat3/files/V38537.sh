#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38537
# Finding ID:	V-38537
# Version:	RHEL-06-000093
# Finding Level:	Low
#
#     The system must ignore ICMPv4 bogus error responses. Ignoring bogus 
#     ICMP error responses reduces log size, although some activity would 
#     not be logged.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "-----------------------------------"
diag_out "STIG Finding ID: V-38537"
diag_out "  System must ignore bogus ICMPv4"
diag_out "  error responses"
diag_out "-----------------------------------"
