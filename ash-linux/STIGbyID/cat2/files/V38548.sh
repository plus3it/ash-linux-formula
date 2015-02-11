#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38548
# Finding ID:	V-38548
# Version:	RHEL-06-000099
# Finding Level:	Medium
#
#     The system must ignore ICMPv6 redirects by default. An illicit ICMP 
#     redirect message could result in a man-in-the-middle attack.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38548"
diag_out "  The system must be configured to"
diag_out "  ICMPv6 redirects by default"
diag_out "----------------------------------"
