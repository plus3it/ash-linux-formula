#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38687
# Finding ID:	V-38687
# Version:	RHEL-06-000321
# Finding Level:	Low
#
#     The system must provide VPN connectivity for communications over 
#     untrusted networks. Providing the ability for remote users or systems 
#     to initiate a secure VPN connection protects information when it is 
#     transmitted over a wide area network.
#
#  CCI: CCI-001130
#  NIST SP 800-53 :: SC-9
#  NIST SP 800-53A :: SC-9.1
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38687"
diag_out "  The system must provide VPN"
diag_out "  connectivity for communications"
diag_out "  over untrusted networks."
diag_out "----------------------------------"
