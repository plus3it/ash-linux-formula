#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38604
# Finding ID:	V-38604
# Version:	RHEL-06-000221
# Finding Level:	Medium
#
#     The ypbind service must not be running. Disabling the "ypbind" 
#     service ensures the system is not acting as a client in a NIS or NIS+ 
#     domain.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38604"
diag_out "  Ensure that NIS-related services"
diag_out "  are not running"
diag_out "----------------------------------"
