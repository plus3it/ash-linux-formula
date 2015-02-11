#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38680
# Finding ID:	V-38680
# Version:	RHEL-06-000313
# Finding Level:	Medium
#
#     The audit system must identify staff members to receive notifications 
#     of audit log storage volume capacity issues. Email sent to the root 
#     account is typically aliased to the administrators of the system, who 
#     can take appropriate action.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38680"
diag_out "  Audit system must send email"
diag_out "  notifications about storage"
diag_out "  capacity to admin group"
diag_out "----------------------------------"

