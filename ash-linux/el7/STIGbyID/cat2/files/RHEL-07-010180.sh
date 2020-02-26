#!/bin/sh
# Finding ID:	RHEL-07-010180
# Version:	RHEL-07-010180_rule
# SRG ID:	SRG-OS-000072-GPOS-00040
# Finding Level:	medium
# 
# Rule Summary:
#	When passwords are changed the number of repeating consecutive
#	characters must not be more than four characters.
#
# CCI-000195 
#    NIST SP 800-53 :: IA-5 (1) (b) 
#    NIST SP 800-53A :: IA-5 (1).1 (v) 
#    NIST SP 800-53 Revision 4 :: IA-5 (1) (b) 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-010180"
diag_out "   When passwords are changed the"
diag_out "   number of repeating consecutive"
diag_out "   characters must not be more than"
diag_out "   four characters."
diag_out "----------------------------------------"
