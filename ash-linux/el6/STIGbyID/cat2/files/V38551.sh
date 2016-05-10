#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38551
# Finding ID:	V-38551
# Version:	RHEL-06-000106
# Finding Level:	Medium
#
#     The operating system must connect to external networks or information 
#     systems only through managed IPv6 interfaces consisting of boundary 
#     protection devices arranged in accordance with an organizational 
#     security architecture. The "ip6tables" service provides the system's 
#     host-based firewalling capability for IPv6 and ICMPv6.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38551"
diag_out "  The system must connect to other"
diag_out "  IPv6-networked hosts only via"
diag_out "  firewall-protected interfaces"
diag_out "----------------------------------"
