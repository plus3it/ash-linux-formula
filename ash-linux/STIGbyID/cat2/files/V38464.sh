#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38464
# Finding ID:	V-38464
# Version:	RHEL-06-000511
# Finding Level:	Medium
#
#     The audit system must take appropriate action when there are disk 
#     errors on the audit storage volume. Taking appropriate action in case 
#     of disk errors will minimize the possibility of losing audit records.
#
#  CCI: CCI-000140
#  NIST SP 800-53 :: AU-5 b
#  NIST SP 800-53A :: AU-5.1 (iv)
#  NIST SP 800-53 Revision 4 :: AU-5 b
#
############################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38464"
diag_out "  Set audit security subsystem's"
diag_out "  disk_error_action parameter to"
diag_out "  'HALT'"
diag_out "----------------------------------"
