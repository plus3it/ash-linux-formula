#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38610
# Finding ID:	V-38610
# Version:	RHEL-06-000231
# Finding Level:	Low
#
#     The SSH daemon must set a timeout count on idle sessions. This 
#     ensures a user login will be terminated as soon as the 
#     "ClientAliveCountMax" is reached.
#
#  CCI: CCI-000879
#  NIST SP 800-53 :: MA-4 e
#  NIST SP 800-53A :: MA-4.1 (vi)
#  NIST SP 800-53 Revision 4 :: MA-4 e
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38610"
diag_out "  SSH daemon must set a timeout"
diag_out "  count on idle sessions"
diag_out "----------------------------------"
