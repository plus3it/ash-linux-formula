#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38627
# Finding ID:	V-38627
# Version:	RHEL-06-000256
# Finding Level:	Low
#
#     The openldap-servers package must not be installed unless required. 
#     Unnecessary packages should not be installed to decrease the attack 
#     surface of the system.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38627"
diag_out "  The openldap-servers package"
diag_out "  must not be installed unless"
diag_out "  required"
diag_out "----------------------------------"
