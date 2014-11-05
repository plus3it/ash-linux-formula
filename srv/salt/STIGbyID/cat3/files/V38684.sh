#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38684
# Finding ID:	V-38684
# Version:	RHEL-06-000319
# Finding Level:	Low
#
#     The system must limit users to 10 simultaneous system logins, or a 
#     site-defined number, in accordance with operational requirements. 
#     Limiting simultaneous user logins can insulate the system from denial 
#     of service problems caused by excessive logins. Automated login 
#     processes operating improperly or maliciously may result in an 
#     exceptional number of simultaneous login sessions.
#
#  CCI: CCI-000054
#  NIST SP 800-53 :: AC-10
#  NIST SP 800-53A :: AC-10.1 (ii)
#  NIST SP 800-53 Revision 4 :: AC-10
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38684"
diag_out "  The system should limit users"
diag_out "  to no more than 10 simultaneous"
diag_out "  system logins"
diag_out "----------------------------------"
