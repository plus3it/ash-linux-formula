#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38663
# Finding ID:	V-38663
# Version:	RHEL-06-000278
# Finding Level:	Medium
#
#     The system package management tool must verify permissions on all 
#     files and directories associated with the audit package. Permissions 
#     on audit binaries and configuration files that are too generous could 
#     allow an unauthorized user to gain privileges that they should not 
#     have. The permissions set by the vendor should be ...
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38663"
diag_out "  Verify that the permissions set"
diag_out "  within the audit RPM are still"
diag_out "  the permissions in place on the"
diag_out "  running system"
diag_out "----------------------------------"

