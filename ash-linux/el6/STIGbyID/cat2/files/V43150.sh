#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-43150
# Finding ID:	V-43150
# Version:	RHEL-06-000527
# Finding Level:	Medium
#
#     The login user list must be disabled. Leaving the user list enabled 
#     is a security risk since it allows anyone with physical access to the 
#     system to quickly enumerate known user accounts without logging in.
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

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-43150"
diag_out "  Graphical login manager must not"
diag_out "  display list of user accounts"
diag_out "----------------------------------"

