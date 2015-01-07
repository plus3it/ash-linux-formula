#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38624
# Finding ID:	V-38624
# Version:	RHEL-06-000138
# Finding Level:	Low
#
#     System logs must be rotated daily. Log files that are not properly 
#     rotated run the risk of growing so large that they fill up the 
#     /var/log partition. Valuable logging information could be lost if the 
#     /var/log partition becomes full.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38624"
diag_out "  System logs must be rotated"
diag_out "  daily"
diag_out "----------------------------------"
