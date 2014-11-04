#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38498
# Finding ID:	V-38498
# Version:	RHEL-06-000383
# Finding Level:	Medium
#
#     Audit log files must have mode 0640 or less permissive. If users can 
#     write to audit logs, audit trails can be modified or destroyed.
#
#  CCI: CCI-000163
#  NIST SP 800-53 :: AU-9
#  NIST SP 800-53A :: AU-9.1
#  NIST SP 800-53 Revision 4 :: AU-9
#
############################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG finding ID: V-38498"
diag_out "  Audit logs must be set to mode"
diag_out "  0640 or more-restrictive"
diag_out "----------------------------------"
