#!/bin/sh
# Finding ID:	RHEL-07-010150
# Version:	RHEL-07-010150_rule
# SRG ID:	SRG-OS-000266-GPOS-00101
# Finding Level:	medium
# 
# Rule Summary:
#	When passwords are changed or new passwords are assigned, the
#	new password must contain at least one special character.
#
# CCI-001619 
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
diag_out "STIG Finding ID: RHEL-07-010150"
diag_out "   When passwords are changed or new"
diag_out "   passwords are assigned, the new"
diag_out "   password must contain at least one"
diag_out "   special character."
diag_out "----------------------------------------"
