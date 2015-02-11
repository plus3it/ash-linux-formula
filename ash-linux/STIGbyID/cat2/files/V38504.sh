#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38504
# Finding ID:	V-38504
# Version:	RHEL-06-000035
# Finding Level:	Medium
#
#     The /etc/shadow file must have mode 0000. The "/etc/shadow" file 
#     contains the list of local system accounts and stores password 
#     hashes. Protection of this file is critical for system security. 
#     Failure to give ownership of this file to root ...
#
############################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38504"
diag_out "  The /etc/shadow file should be"
diag_out "  set to mode 0000"
diag_out "----------------------------------"
