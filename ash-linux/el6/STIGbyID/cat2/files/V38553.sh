#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38553
# Finding ID:	V-38553
# Version:	RHEL-06-000107
# Finding Level:	Medium
#
#     The operating system must prevent public IPv6 access into an 
#     organizations internal networks, except as appropriately mediated by 
#     managed interfaces employing boundary protection devices. The 
#     "ip6tables" service provides the system's host-based firewalling 
#     capability for IPv6 and ICMPv6.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38553"
diag_out "  The operating system must"
diag_out "  prevent public IPv6-based access"
diag_out "  except where governed by a"
diag_out "  firewall"
diag_out "----------------------------------"
