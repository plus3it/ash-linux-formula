#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38494
# Finding ID:	V-38494
# Version:	RHEL-06-000028
# Finding Level:	Low
#
#     The system must prevent the root account from logging in from serial 
#     consoles. Preventing direct root login to serial port interfaces 
#     helps ensure accountability for actions taken on the systems using 
#     the root account.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38494"
diag_out "  root account must be prohibited"
diag_out "  from logging in from serial"
diag_out "  consoles"
diag_out "----------------------------------"
