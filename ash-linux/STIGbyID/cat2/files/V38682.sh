#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38682
# Finding ID:	V-38682
# Version:	RHEL-06-000315
# Finding Level:	Medium
#
#     The Bluetooth kernel module must be disabled. If Bluetooth 
#     functionality must be disabled, preventing the kernel from loading 
#     the kernel module provides an additional safeguard against its 
#     activation.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38682"
diag_out "  The Bluetooth kernel module must"
diag_out "  be disabled."
diag_out "----------------------------------"

