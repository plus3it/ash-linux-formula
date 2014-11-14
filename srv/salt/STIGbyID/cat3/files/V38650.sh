#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38650
# Finding ID:	V-38650
# Version:	RHEL-06-000268
# Finding Level:	Low
#
#     The rdisc service must not be running. General-purpose systems 
#     typically have their network and routing information configured 
#     statically by a system administrator. Workstations or some 
#     special-purpose systems often use DHCP (instead of IRDP) to retrieve 
#     dynamic network configuration information. 
#
#  CCI: CCI-000382
#  NIST SP 800-53 :: CM-7
#  NIST SP 800-53A :: CM-7.1 (iii)
#  NIST SP 800-53 Revision 4 :: CM-7 b
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38650"
diag_out "  The rdisc service must not be"
diag_out "  running."
diag_out "----------------------------------"
