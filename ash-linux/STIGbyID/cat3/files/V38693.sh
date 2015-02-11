#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38693
# Finding ID:	V-38693
# Version:	RHEL-06-000299
# Finding Level:	Low
#
#     The system must require passwords to contain no more than three 
#     consecutive repeating characters. Passwords with excessive repeating 
#     characters may be more vulnerable to password-guessing attacks.
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
diag_out "STIG Finding ID: V-38693"
diag_out "  The system must require"
diag_out "  passwords to contain no more"
diag_out "  than three consecutive"
diag_out "  repeating characters."
diag_out "----------------------------------"
