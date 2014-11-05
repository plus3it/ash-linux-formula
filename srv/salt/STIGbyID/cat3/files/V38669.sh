#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38669
# Finding ID:	V-38669
# Version:	RHEL-06-000287
# Finding Level:	Low
#
#     The postfix service must be enabled for mail delivery. Local mail 
#     delivery is essential to some system maintenance and notification 
#     tasks.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38669"
diag_out "  The postfix service must be"
diag_out "  enabled for mail delivery."
diag_out "----------------------------------"
