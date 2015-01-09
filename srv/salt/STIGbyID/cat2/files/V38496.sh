#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38496
# Finding ID:	V-38496
# Version:	RHEL-06-000029
# Finding Level:	Medium
#
#     Default operating system accounts, other than root, must be locked. 
#     Disabling authentication for default system accounts makes it more 
#     difficult for attackers to make use of them to compromise a system.
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

diag_out "------------------------------------"
diag_out "STIG Finding ID: V-38496"
diag_out "  Default operating system accounts,"
diag_out "  other than 'root' (uid 0 >< 500),"
diag_out "  must be locked."
diag_out "------------------------------------"
