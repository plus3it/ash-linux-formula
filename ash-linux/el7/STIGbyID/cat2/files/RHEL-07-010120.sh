#!/bin/sh
# Finding ID:	RHEL-07-010120
# Version:	RHEL-07-010120_rule
# SRG ID:	SRG-OS-000069-GPOS-00037
# Finding Level:	medium
# 
# Rule Summary:
#	When passwords are changed or new passwords are established,
#	the new password must contain at least one upper-case character.
#
# CCI-000192 
#    NIST SP 800-53 :: IA-5 (1) (a) 
#    NIST SP 800-53A :: IA-5 (1).1 (v) 
#    NIST SP 800-53 Revision 4 :: IA-5 (1) (a) 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-010120"
diag_out "   When passwords are changed or new"
diag_out "   passwords are established, the new"
diag_out "   password must contain at least one"
diag_out "   upper-case character."
diag_out "----------------------------------------"
