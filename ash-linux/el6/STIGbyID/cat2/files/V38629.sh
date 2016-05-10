#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38629
# Finding ID:	V-38629
# Version:	RHEL-06-000257
# Finding Level:	Medium
#
#     The graphical desktop environment must set the idle timeout to no 
#     more than 15 minutes. Setting the idle delay controls when the 
#     screensaver will start, and can be combined with screen locking to 
#     prevent access from passersby.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38629"
diag_out "  Graphical desktop environments"
diag_out "  must lock the screen if there"
diag_out "  has been no user activity for 15"
diag_out "  minutes"
diag_out "----------------------------------"
