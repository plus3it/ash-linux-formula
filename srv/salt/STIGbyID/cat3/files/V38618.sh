#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38618
# Finding ID:	V-38618
# Version:	RHEL-06-000246
# Finding Level:	Low
#
#     The avahi service must be disabled. Because the Avahi daemon service 
#     keeps an open network port, it is subject to network attacks. Its 
#     functionality is convenient but is only appropriate if the local 
#     network can be trusted.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38618"
diag_out "  Avahi service must be disabled"
diag_out "----------------------------------"
