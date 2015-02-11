#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-51337
# Finding ID:	V-51337
# Version:	RHEL-06-000017
# Finding Level:	Medium
#
#     Disabling a major host protection feature, such as SELinux, at boot 
#     time prevents it from confining system services at boot time. Further, 
#     it increases the chances that it will remain off during system 
#     operation. 
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
#############################################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-51337"
diag_out "  SELinux must be active"
diag_out "  throughout boot process and OS"
diag_out "  epoch"
diag_out "----------------------------------"
