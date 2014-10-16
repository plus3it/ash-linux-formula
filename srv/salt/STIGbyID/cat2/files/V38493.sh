#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38493
# Finding ID:	V-38493
# Version:	RHEL-06-000385
# Finding Level:	Medium
#
#     Audit log directories must have mode 0755 or less permissive. If 
#     users can delete audit logs, audit trails can be modified or 
#     destroyed.
#
############################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38493"
diag_out "  Audit log directories must be"
diag_out "  protected from modification by"
diag_out "  non-privileged users"
diag_out "----------------------------------"
