#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38685
# Finding ID:	V-38685
# Version:	RHEL-06-000297
# Finding Level:	Low
#
#     Temporary accounts must be provisioned with an expiration date. When 
#     temporary accounts are created, there is a risk they may remain in 
#     place and active after the need for them no longer exists. Account 
#     expiration greatly reduces the risk of accounts being misused or
#     hijacked.
#
#  CCI: CCI-000016
#  NIST SP 800-53 :: AC-2 (2)
#  NIST SP 800-53A :: AC-2 (2).1 (ii)
#  NIST SP 800-53 Revision 4 :: AC-2 (2)
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38685"
diag_out "  Temporary accounts must be"
diag_out "  provisioned with an expiration"
diag_out "  date."
diag_out "----------------------------------"
