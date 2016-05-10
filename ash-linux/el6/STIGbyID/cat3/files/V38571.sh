#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38571
# Finding ID:	V-38571
# Version:	RHEL-06-000059
# Finding Level:	Low
#
#     The system must require passwords to contain at least one lowercase 
#     alphabetic character. Requiring a minimum number of lowercase 
#     characters makes password guessing attacks more difficult by ensuring 
#     a larger search space.
#
#  CCI: CCI-000193
#  NIST SP 800-53 :: IA-5 (1) (a)
#  NIST SP 800-53A :: IA-5 (1).1 (v)
#  NIST SP 800-53 Revision 4 :: IA-5 (1) (a)
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38571"
diag_out "  System must require passwords"
diag_out "  to contain at least one"
diag_out "  lowercase alphabetic character"
diag_out "----------------------------------"
