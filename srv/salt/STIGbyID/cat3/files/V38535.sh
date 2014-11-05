#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38535
# Finding ID:	V-38535
# Version:	RHEL-06-000092
# Finding Level:	Low
#
#     The system must not respond to ICMPv4 sent to a broadcast address. 
#     Ignoring ICMP echo requests (pings) sent to broadcast or multicast 
#     addresses makes the system slightly more difficult to enumerate on 
#     the network.
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
diag_out "STIG Finding ID: V-38535"
diag_out "  System must not respond to"
diag_out "  ICMPv4 sent to a broadcast"
diag_out "  address"
diag_out "-----------------------------------"
