#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38474
# Finding ID:	V-38474
# Version:	RHEL-06-000508
# Finding Level:	Low
#
#     The system must allow locking of graphical desktop sessions. The 
#     ability to lock graphical desktop sessions manually allows users to 
#     easily secure their accounts should they need to depart from their 
#     workstations temporarily.
#
#  CCI: CCI-000058
#  NIST SP 800-53 :: AC-11 a
#  NIST SP 800-53A :: AC-11
#  NIST SP 800-53 Revision 4 :: AC-11 a
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38474"
diag_out "  System must support locking of"
diag_out "  graphical desktop"
diag_out "----------------------------------"
