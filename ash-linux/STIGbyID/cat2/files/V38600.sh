#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38600
# Finding ID:	V-38600
# Version:	RHEL-06-000080
# Finding Level:	Medium
#
#     The system must not send ICMPv4 redirects by default. Sending ICMP 
#     redirects permits the system to instruct other systems to update 
#     their routing information. The ability to send ICMP redirects is only 
#     appropriate for routers.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38600"
diag_out "  Prevent host from sending ICMP"
diag_out "  redirect packets"
diag_out "----------------------------------"
