#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38691
# Finding ID:	V-38691
# Version:	RHEL-06-000331
# Finding Level:	Medium
#
#     The Bluetooth service must be disabled. Disabling the "bluetooth" 
#     service prevents the system from attempting connections to Bluetooth 
#     devices, which entails some security risk. Nevertheless, variation in 
#     this risk decision may be expected ...
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38691"
diag_out "  Disable the BlueTooth service"
diag_out "----------------------------------"

