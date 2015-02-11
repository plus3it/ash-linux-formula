#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38603
# Finding ID:	V-38603
# Version:	RHEL-06-000220
# Finding Level:	Medium
#
#     The ypserv package must not be installed. Removing the "ypserv" 
#     package decreases the risk of the accidental (or intentional) 
#     activation of NIS or NIS+ services.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38603"
diag_out "  NIS-related packages must be"
diag_out "  removed from the system"
diag_out "----------------------------------"
