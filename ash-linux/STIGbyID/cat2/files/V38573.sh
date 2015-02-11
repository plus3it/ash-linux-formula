#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38573
# Finding ID:	V-38573
# Version:	RHEL-06-000061
# Finding Level:	Medium
#
#     The system must disable accounts after three consecutive unsuccessful 
#     login attempts. Locking out user accounts after a number of incorrect 
#     attempts prevents direct password guessing attacks.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38573"
diag_out "  The system must disable accounts"
diag_out "  after three, consecutive failed"
diag_out "  login attempts"
diag_out "----------------------------------"
