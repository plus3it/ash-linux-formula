#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-51391
# Finding ID:	V-51391
# Version:	RHEL-06-000018
# Finding Level:	Medium
#
#     A file integrity baseline must be created. For AIDE to be effective, 
#     an initial database of "known-good" information about files must be 
#     captured and it should be able to be verified against the installed 
#     files.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-51391"
diag_out "  An AIDE database must be"
diag_out "  available for system file"
diag_out "  verification"
diag_out "----------------------------------"
