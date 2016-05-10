#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38681
# Finding ID:	V-38681
# Version:	RHEL-06-000294
# Finding Level:	Low
#
#     All GIDs referenced in /etc/passwd must be defined in /etc/group 
#     Inconsistency in GIDs between /etc/passwd and /etc/group could lead 
#     to a user having unintended rights.
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
diag_out "STIG Finding ID: V-38681"
diag_out "  All GIDs referenced in"
diag_out "  /etc/passwd must be defined in"
diag_out "  /etc/group"
diag_out "----------------------------------"
