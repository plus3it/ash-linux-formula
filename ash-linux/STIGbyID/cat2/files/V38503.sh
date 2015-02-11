#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38503
# Finding ID:	V-38503
# Version:	RHEL-06-000034
# Finding Level:	Medium
#
#     The /etc/shadow file must be group-owned by root. The "/etc/shadow" 
#     file stores password hashes. Protection of this file is critical for 
#     system security.
#
############################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38503"
diag_out "  The /etc/shadow file must be"
diag_out "  group-owned by root"
diag_out "----------------------------------"
