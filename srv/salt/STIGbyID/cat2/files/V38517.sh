#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38517
# Finding ID:	V-38517
# Version:	RHEL-06-000127
# Finding Level:	Medium
#
#     The Transparent Inter-Process Communication (TIPC) protocol must be 
#     disabled unless required. Disabling TIPC protects the system against 
#     exploitation of any flaws in its implementation.
#
############################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38517"
diag_out "  The Transparent Inter-Process"
diag_out "  Communication Protocol (TIPC)"
diag_out "  must be disabled"
diag_out "----------------------------------"
