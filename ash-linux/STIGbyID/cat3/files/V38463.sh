#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38463
# Finding ID:	V-38463
# Version:	RHEL-06-000003
# Finding Level:	Low
#
#     The system must use a separate file system for /var/log. Placing 
#     "/var/log" in its own partition enables better separation between log 
#     files and other files in "/var/".
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
diag_out "STIG Finding ID: V-38463"
diag_out "  The /var/log directory should be"
diag_out "  on its own device"
diag_out "----------------------------------"
