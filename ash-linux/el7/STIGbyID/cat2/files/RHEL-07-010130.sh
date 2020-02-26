#!/bin/sh
# Finding ID:	RHEL-07-010130
# Version:	RHEL-07-010130_rule
# SRG ID:	SRG-OS-000070-GPOS-00038
# Finding Level:	medium
# 
# Rule Summary:
#	When passwords are changed or new passwords are established,
#	the new password must contain at least one lower-case
#	character.
#
# CCI-000193 
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
diag_out "STIG Finding ID: RHEL-07-010130"
diag_out "   When passwords are changed or new"
diag_out "   passwords are established, the new"
diag_out "   password must contain at least one"
diag_out "   lower-case character."
diag_out "----------------------------------------"
