#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38651
# Finding ID:	V-38651
# Version:	RHEL-06-000342
# Finding Level:	Low
#
#     The umask value influences the permissions assigned to files when 
#     they are created. A misconfigured umask value could result in files 
#     with excessive permissions that can be read and/or written to by 
#     unauthorized users. 
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################
 
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38651"
diag_out "  The system default umask for"
diag_out "  the bash shell must be 077."
diag_out "----------------------------------"
