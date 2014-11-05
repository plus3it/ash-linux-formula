#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38608
# Finding ID:	V-38608
# Version:	RHEL-06-000230
# Finding Level:	Low
#
#     The SSH daemon must set a timeout interval on idle sessions. Causing 
#     idle users to be automatically logged out guards against compromises 
#     one system leading trivially to compromises on another.
#
#  CCI: CCI-001133
#  NIST SP 800-53 :: SC-10
#  NIST SP 800-53A :: SC-10.1 (ii)
#  NIST SP 800-53 Revision 4 :: SC-10
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38608"
diag_out "  SSH daemon must set a timeout"
diag_out "  interval on idle sessions"
diag_out "----------------------------------"
