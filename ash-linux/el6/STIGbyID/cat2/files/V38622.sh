#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38622
# Finding ID:	V-38622
# Version:	RHEL-06-000249
# Finding Level:	Medium
#
#     Mail relaying must be restricted. This ensures "postfix" accepts mail 
#     messages (such as cron job reports) from the local system only, and 
#     not from the network, which protects it from network attack.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38622"
diag_out "  SMTP service must be configured"
diag_out "  to prohibit relaying"
diag_out "----------------------------------"
