#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38457
# Finding ID:	V-38457
# Version:	RHEL-06-000041
# Finding Level:	Medium
#
#     The /etc/passwd file must have mode 0644 or less permissive. If the 
#     "/etc/passwd" file is writable by a group-owner or the world the risk 
#     of its compromise is increased. The file contains the list of 
#     accounts on the system and associated information, and ...
#
############################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38457"
diag_out "  Ensure passwd file is set to"
diag_out "  mode 0644 (or better)"
diag_out "----------------------------------"

