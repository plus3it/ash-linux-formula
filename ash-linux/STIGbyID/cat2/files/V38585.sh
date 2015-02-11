#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38585
# Finding ID:	V-38585
# Version:	RHEL-06-000068
# Finding Level:	Medium
#
#     The system boot loader must require authentication. Password 
#     protection on the boot loader configuration ensures users with 
#     physical access cannot trivially alter important bootloader settings. 
#     These include which kernel to use, and whether to enter ...
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38585"
diag_out "  System boot-loader must require"
diag_out "  a SHA512-encrypted password to"
diag_out "  alter boot-time settings"
diag_out "----------------------------------"
