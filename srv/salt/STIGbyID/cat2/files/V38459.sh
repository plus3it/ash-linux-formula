#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38459
# Finding ID:	V-38459
# Version:	RHEL-06-000043
# Finding Level:	Medium
#
#     The /etc/group file must be group-owned by root. The "/etc/group" 
#     file contains information regarding groups that are configured on the 
#     system. Protection of this file is important for system security.
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
diag_out "STIG Finding ID: V-38459"
diag_out "  Ensure /etc/group file is owned"
diag_out "  by the root group"
diag_out "----------------------------------"

