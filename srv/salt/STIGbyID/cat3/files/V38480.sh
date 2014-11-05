#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38480
# Finding ID:	V-38480
# Version:	RHEL-06-000054
# Finding Level:	Low
#
#     Users must be warned 7 days in advance of password expiration. 
#     Setting the password warning age enables users to make the change at 
#     a practical time.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38480"
diag_out "  Local users must be notified of"
diag_out "  pending password-expiry at least"
diag_out "  7 days in advance"
diag_out "----------------------------------"
