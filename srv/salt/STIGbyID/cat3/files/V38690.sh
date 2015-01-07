#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38690
# Finding ID:	V-38690
# Version:	RHEL-06-000298
# Finding Level:	Low
#
#     Emergency accounts must be provisioned with an expiration date. When 
#     emergency accounts are created, there is a risk they may remain in 
#     place and active after the need for them no longer exists. Account 
#     expiration greatly reduces the risk of accounts being misused
#     or hijacked.
#
#  CCI: CCI-001682
#  NIST SP 800-53 :: AC-2 (2)
#  NIST SP 800-53A :: AC-2 (2).1 (ii)
#  NIST SP 800-53 Revision 4 :: AC-2 (2)
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38690"
diag_out "  Emergency accounts must be"
diag_out "  provisioned with an expiration"
diag_out "  date."
diag_out "----------------------------------"
