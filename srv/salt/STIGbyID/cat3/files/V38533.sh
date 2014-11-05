#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38533
# Finding ID:	V-38533
# Version:	RHEL-06-000091
# Finding Level:	Low
#
#     The system must ignore ICMPv4 redirect messages by default. This 
#     feature of the IPv4 protocol has few legitimate uses. It should be 
#     disabled unless it is absolutely required.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "-----------------------------------"
diag_out "STIG Finding ID: V-38533"
diag_out "  System must ignore ICMPv4" 
diag_out "  redirect messages by default"
diag_out "-----------------------------------"
