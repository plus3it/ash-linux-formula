#!/bin/sh
# Finding ID:	RHEL-07-010280
# Version:	RHEL-07-010280_rule
# SRG ID:	SRG-OS-000078-GPOS-00046
# Finding Level:	medium
# 
# Rule Summary:
#	Passwords must be a minimum of 15 characters in length.
#
# CCI-000205 
#    NIST SP 800-53 :: IA-5 (1) (a) 
#    NIST SP 800-53A :: IA-5 (1).1 (i) 
#    NIST SP 800-53 Revision 4 :: IA-5 (1) (a) 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-010280"
diag_out "   Passwords must be a minimum of 15"
diag_out "   characters in length."
diag_out "----------------------------------------"
