#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38569
# Finding ID:	V-38569
# Version:	RHEL-06-000057
# Finding Level:	Low
#
#     The system must require passwords to contain at least one uppercase 
#     alphabetic character. Requiring a minimum number of uppercase 
#     characters makes password guessing attacks more difficult by ensuring 
#     a larger search space.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38569"
diag_out "  System must require passwords"
diag_out "  to contain at least one"
diag_out "  uppercase alphabetic character"
diag_out "----------------------------------"
