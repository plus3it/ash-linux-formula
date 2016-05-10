#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38671
# Finding ID:	V-38671
# Version:	RHEL-06-000288
# Finding Level:	Medium
#
#     The sendmail package must be removed. The sendmail software was not 
#     developed with security in mind and its design prevents it from being 
#     effectively contained by SELinux. Postfix should be used instead.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38671"
diag_out "  The Sendmail package must be"
diag_out "  removed"
diag_out "----------------------------------"

