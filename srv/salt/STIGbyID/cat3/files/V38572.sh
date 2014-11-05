#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38572
# Finding ID:	V-38572
# Version:	RHEL-06-000060
# Finding Level:	Low
#
#     The system must require at least four characters be changed between 
#     the old and new passwords during a password change. Requiring a 
#     minimum number of different characters during password changes 
#     ensures that newly changed passwords should not resemble previously 
#     compromised ones. Note that passwords which are changed on 
#     compromised systems will still be compromised, however. 
#
#  CCI: CCI-000195
#  NIST SP 800-53 :: IA-5 (1) (b)
#  NIST SP 800-53A :: IA-5 (1).1 (v)
#  NIST SP 800-53 Revision 4 :: IA-5 (1) (b)
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38572"
diag_out "  System must require at least"
diag_out "  four characters be changed"
diag_out "  between the old and new"
diag_out "  passwords during a password"
diag_out "  change"
diag_out "----------------------------------"
