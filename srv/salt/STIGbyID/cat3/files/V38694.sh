#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38694
# Finding ID:	V-38694
# Version:	RHEL-06-000335
# Finding Level:	Low
#
#     The operating system must manage information system identifiers for 
#     users and devices by disabling the user identifier after an 
#     organization defined time period of inactivity. Disabling inactive 
#     accounts ensures that accounts which may not have been responsibly 
#     removed are not available to attackers who may have compromised their 
#     credentials.
#
#  CCI: CCI-000795
#  NIST SP 800-53 :: IA-4 e
#  NIST SP 800-53A :: IA-4.1 (iii)
#  NIST SP 800-53 Revision 4 :: IA-4 e
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38694"
diag_out "  System must automatically"
diag_out "  disable inactive accounts."
diag_out "----------------------------------"
