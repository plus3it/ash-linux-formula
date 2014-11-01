#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38512
# Finding ID:	V-38512
# Version:	RHEL-06-000117
# Finding Level:	Medium
#
#     The operating system must prevent public IPv4 access into an 
#     organizations internal networks, except as appropriately mediated by 
#     managed interfaces employing boundary protection devices. The 
#     "iptables" service provides the system's host-based firewalling 
#     capability for IPv4 and ICMP.
#
#  CCI: CCI-001100
#  NIST SP 800-53 :: SC-7 (2)
#  NIST SP 800-53A :: SC-7 (2).1 (ii)
#
############################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38512"
diag_out "  Enable the iptables service"
diag_out "----------------------------------"
