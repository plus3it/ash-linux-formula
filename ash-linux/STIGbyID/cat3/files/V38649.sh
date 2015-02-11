#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38649
# Finding ID:	V-38649
# Version:	RHEL-06-000343
# Finding Level:	Low
#
#     The system default umask for the csh shell must be 077. The umask 
#     value influences the permissions assigned to files when they are 
#     created. A misconfigured umask value could result in files with 
#     excessive permissions that can be read and/or written to by 
#     unauthorized users. 
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "  The system default umask for"
diag_out "  the csh shell must be 077."
diag_out "----------------------------------"
