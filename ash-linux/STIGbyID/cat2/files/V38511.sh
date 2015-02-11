#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38511
# Finding ID:	V-38511
# Version:	RHEL-06-000082
# Finding Level:	Medium
#
#     IP forwarding for IPv4 must not be enabled, unless the system is a 
#     router. IP forwarding permits the kernel to forward packets from one 
#     network interface to another. The ability to forward packets between 
#     two networks is only appropriate for routers.
#
############################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38511"
diag_out "  Disable IP-forwarding for IPv4"
diag_out "  for any system not meant to act"
diag_out "   as a router"
diag_out "----------------------------------"
