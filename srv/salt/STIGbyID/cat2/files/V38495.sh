#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38495
# Finding ID:	V-38495
# Version:	RHEL-06-000384
# Finding Level:	Medium
#
#     Audit log files must be owned by root. If non-privileged users can 
#     write to audit logs, audit trails can be modified or destroyed.
#
#  CCI: CCI-000162
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
diag_out "STIG Finding ID: V-38495"
diag_out "  Audit log directories and files"
diag_out "  must be owned by the root user"
diag_out "----------------------------------"
