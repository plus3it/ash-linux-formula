#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38619
# Finding ID:	V-38619
# Version:	RHEL-06-000347
# Finding Level:	Medium
#
#     There must be no .netrc files on the system. Unencrypted passwords 
#     for remote FTP servers may be stored in ".netrc" files. DoD policy 
#     requires passwords be encrypted in storage and not used in access 
#     scripts.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38619"
diag_out "  there must be not .netrc files"
diag_out "  on the system"
diag_out "----------------------------------"
