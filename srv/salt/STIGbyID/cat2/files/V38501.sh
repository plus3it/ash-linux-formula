#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38501
# Finding ID:	V-38501
# Version:	
# Finding Level:	Medium
#
#     The system must disable accounts after excessive login failures 
#     within a 15-minute interval. Locking out user accounts after a number 
#     of incorrect attempts within a specific period of time prevents 
#     direct password guessing attacks.
#
############################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38501"
diag_out "  authentication-failure check-"
diag_out "  interval should be set to 15"
diag_out "  minutes or less"
diag_out "----------------------------------"
