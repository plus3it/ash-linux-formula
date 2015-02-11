#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38500
# Finding ID:	V-38500
# Version:	RHEL-06-000032
# Finding Level:	Medium
#
#     The root account must be the only account having a UID of 0. An 
#     account has root authority if it has a UID of 0. Multiple accounts 
#     with a UID of 0 afford more opportunity for potential intruders to 
#     guess a password for a privileged account. Proper ...
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
diag_out "STIG Finding ID: V-38500"
diag_out "  Only the root user may have the"
diag_out "  uid '0'"
diag_out "----------------------------------"
