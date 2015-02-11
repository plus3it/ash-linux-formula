#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38555
# Finding ID:	V-38555
# Version:	RHEL-06-000113
# Finding Level:	Medium
#
#     The system must employ a local IPv4 firewall. The "iptables" service 
#     provides the system's host-based firewalling capability for IPv4 and 
#     ICMP.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38555"
diag_out "  The iptables service must be"
diag_out "  enabled for IPv4 and ICMP"
diag_out "----------------------------------"
