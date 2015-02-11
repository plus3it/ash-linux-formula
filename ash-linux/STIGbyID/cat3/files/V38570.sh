#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38570
# Finding ID:	V-38570
# Version:	RHEL-06-000058
# Finding Level:	Low
#
#     The system must require passwords to contain at least one special 
#     character. Requiring a minimum number of special characters makes 
#     password guessing attacks more difficult by ensuring a larger search 
#     space.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38570"
diag_out "  system must require passwords"
diag_out "  to contain at least one special"
diag_out "  character."
diag_out "----------------------------------"
