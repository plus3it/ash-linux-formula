#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38575
# Finding ID:	V-38575
# Version:	RHEL-06-000200
# Finding Level:	Low
#
#     The audit system must be configured to audit user deletions of files 
#     and programs. Auditing file deletions will create an audit trail for 
#     files that are removed from the system. The audit trail could aid in 
#     system troubleshooting, as well as detecting malicious processes that 
#     that attempt to delete log files to conceal their presence. 
#
#  CCI: CCI-000172
#  NIST SP 800-53 :: AU-12 c
#  NIST SP 800-53A :: AU-12.1 (iv)
#  NIST SP 800-53 Revision 4 :: AU-12 c
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38575"
diag_out "  Audit system must log user"
diag_out "  deletions of files and programs"
diag_out "----------------------------------"
