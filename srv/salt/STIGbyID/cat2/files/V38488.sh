#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38488
# Finding ID:	V-38488
# Version:	RHEL-06-000504
# Finding Level:	Medium
#
#     Operating system backup is a critical step in maintaining data
#     assurance and availability. User-level information is data generated
#     by information system and/or application users. Backups shall be
#     consistent with organizational recovery time and recovery point
#     objectives.
#
#  CCI: CCI-000535
#  NIST SP 800-53 :: CP-9 (a)
#  NIST SP 800-53A :: CP-9.1 (iv)
#  NIST SP 800-53 Revision 4 :: CP-9 (a)
#
##########################################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38488"
diag_out "  Ascertain if system is protected"
diag_out "  through backups of aplication"
diag_out "  and/or user data"
diag_out "----------------------------------"
