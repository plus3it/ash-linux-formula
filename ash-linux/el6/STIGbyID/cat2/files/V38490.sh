#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38490
# Finding ID:	V-38490
# Version:	RHEL-06-000503
# Finding Level:	Medium
#
#     The operating system must enforce requirements for the connection of 
#     mobile devices to operating systems. USB storage devices such as 
#     thumb drives can be used to introduce unauthorized software and other 
#     vulnerabilities. Support for these devices should be disabled and the 
#     devices themselves should be ...
#
############################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG finding ID: V-38490"
diag_out "  Ascertain if system is protected"
diag_out "  through backups of aplication"
diag_out "  and/or user data"
diag_out "----------------------------------"
