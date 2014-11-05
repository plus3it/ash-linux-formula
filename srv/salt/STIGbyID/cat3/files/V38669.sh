#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38669
# Finding ID:	V-38669
# Version:	RHEL-06-000287
# Finding Level:	Low
#
#     The postfix service must be enabled for mail delivery. Local mail 
#     delivery is essential to some system maintenance and notification 
#     tasks.
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
diag_out "STIG Finding ID: V-38669"
diag_out "  The postfix service must be"
diag_out "  enabled for mail delivery."
diag_out "----------------------------------"
