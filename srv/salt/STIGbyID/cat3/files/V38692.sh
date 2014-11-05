#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38692
# Finding ID:	V-38692
# Version:	RHEL-06-000334
# Finding Level:	Low
#
#     Accounts must be locked upon 35 days of inactivity. Disabling 
#     inactive accounts ensures that accounts which may not have been 
#     responsibly removed are not available to attackers who may have 
#     compromised their credentials.
#
#  CCI: CCI-000017
#  NIST SP 800-53 :: AC-2 (3)
#  NIST SP 800-53A :: AC-2 (3).1 (ii)
#  NIST SP 800-53 Revision 4 :: AC-2 (3)
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38692"
diag_out "  Accounts must be locked upon 35"
diag_out "  days of inactivity."
diag_out "----------------------------------"
