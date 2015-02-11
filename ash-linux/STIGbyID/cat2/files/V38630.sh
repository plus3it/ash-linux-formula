#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38630
# Finding ID:	V-38630
# Version:	RHEL-06-000258
# Finding Level:	Medium
#
#     The graphical desktop environment must automatically lock after 15 
#     minutes of inactivity and the system must require user to 
#     re-authenticate to unlock the environment. Enabling idle activation 
#     of the screen saver ensures the screensaver will be activated after 
#     the idle delay. Applications requiring continuous, real-time screen 
#     display (such as network management ...
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38630"
diag_out "  Graphical desktop environments"
diag_out "  must lock the screen if there"
diag_out "  has been no user activity for 15"
diag_out "  minutes and must re-authenticate"
diag_out "  to unlock"
diag_out "----------------------------------"
