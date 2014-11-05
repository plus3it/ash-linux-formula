#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38452
# Finding ID:	V-38452
# Version:	RHEL-06-000518
# Finding Level:	Low
#
#     Permissions on system binaries and configuration files that are too 
#     generous could allow an unauthorized user to gain privileges that 
#     they should not have. The permissions set by the vendor should be 
#     maintained. Any deviations from this baseline should be investigated. 
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
diag_out "STIG Finding ID: V-38452"
diag_out "  Verify permissions on all files"
diag_out "  and directories associated with"
diag_out "  packages"
diag_out "----------------------------------"
