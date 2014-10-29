#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38674
# Finding ID:	V-38674
# Version:	RHEL-06-000290
# Finding Level:	Medium
#
#     X Windows must not be enabled unless required. Unnecessary services 
#     should be disabled to decrease the attack surface of the system.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38674"
diag_out "  X Windows must not be enabled "
diag_out "  unless required"
diag_out "----------------------------------"

