#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38683
# Finding ID:	V-38683
# Version:	RHEL-06-000296
# Finding Level:	Low
#
#     All accounts on the system must have unique user or account names 
#     Unique usernames allow for accountability on the system.
#
#  CCI: CCI-000804
#  NIST SP 800-53 :: IA-8
#  NIST SP 800-53A :: IA-8.1
#  NIST SP 800-53 Revision 4 :: IA-8
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38683"
diag_out "  All accounts on the system must"
diag_out "  have unique user or account"
diag_out "  names"
diag_out "----------------------------------"
