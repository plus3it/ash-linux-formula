#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38639
# Finding ID:	V-38639
# Version:	RHEL-06-000260
# Finding Level:	Low
#
#     The system must display a publicly-viewable pattern during a 
#     graphical desktop environment session lock. Setting the screensaver 
#     mode to blank-only conceals the contents of the display from 
#     passersby.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38639"
diag_out "  System must display a"
diag_out "  publicly-viewable pattern"
diag_out "  during a graphical desktop"
diag_out "  environment session lock"
diag_out "----------------------------------"
