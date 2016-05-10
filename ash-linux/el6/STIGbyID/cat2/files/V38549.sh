#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38549
# Finding ID:	V-38549
# Version:	RHEL-06-000103
# Finding Level:	Medium
#
#     The system must employ a local IPv6 firewall. The "ip6tables" service 
#     provides the system's host-based firewalling capability for IPv6 and 
#     ICMPv6.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38549"
diag_out "  The system must employ an host-"
diag_out "  based IPv6 firewall"
diag_out "----------------------------------"
