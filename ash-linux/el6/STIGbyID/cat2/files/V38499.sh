#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38499
# Finding ID:	V-38499
# Version:	RHEL-06-000031
# Finding Level:	Medium
#
#     The /etc/passwd file must not contain password hashes. The hashes for 
#     all user account passwords should be stored in the file "/etc/shadow" 
#     and never in "/etc/passwd", which is readable by all users.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38499"
diag_out "  /etc/passwd file must not"
diag_out "  contain any password hashes"
diag_out "----------------------------------"
