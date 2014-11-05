#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38616
# Finding ID:	V-38616
# Version:	RHEL-06-000241
# Finding Level:	Low
#
#     The SSH daemon must not permit user environment settings. SSH 
#     environment options potentially allow users to bypass access 
#     restriction in some configurations.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38616"
diag_out "  SSH daemon must not permit user"
diag_out "  environment settings"
diag_out "----------------------------------"
