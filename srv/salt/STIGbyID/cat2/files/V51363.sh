#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-51363
# Finding ID:	V-51363
# Version:	RHEL-06-000020
# Finding Level:	Medium
#
#     Setting the SELinux state to enforcing ensures SELinux is able to 
#     confine potentially compromised processes to the security policy, which 
#     is designed to prevent them from causing damage to the system or 
#     further elevating their privileges. 
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
##############################################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-51363"
diag_out "  SELinux must be set to run in"
diag_out "  enforcing mode"
diag_out "----------------------------------"
