#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38638
# Finding ID:	V-38638
# Version:	RHEL-06-000259
# Finding Level:	Medium
#
#     The graphical desktop environment must have automatic lock enabled. 
#     Enabling the activation of the screen lock after an idle period 
#     ensures password entry will be required in order to access the 
#     system, preventing access by passersby.
#
############################################################


diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38638"
diag_out "  graphical desktop environment"
diag_out "  must have automatic lock enabled"
diag_out "----------------------------------"
