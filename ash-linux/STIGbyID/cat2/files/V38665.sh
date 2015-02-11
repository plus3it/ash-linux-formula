#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38665
# Finding ID:	V-38665
# Version:	RHEL-06-000280
# Finding Level:	Medium
#
#     The system package management tool must verify group-ownership on all 
#     files and directories associated with the audit package. 
#     Group-ownership of audit binaries and configuration files that is 
#     incorrect could allow an unauthorized user to gain privileges that 
#     they should not have. The group-ownership set by the vendor should ...
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38665"
diag_out "  Verify that the group ownerships"
diag_out "  set within the audit RPM are"
diag_out "  the group ownerships in place on"
diag_out "  the running system"
diag_out "----------------------------------"

