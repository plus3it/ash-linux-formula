#!/bin/sh
# Finding ID:	RHEL-07-010240
# Version:	RHEL-07-010240_rule
# SRG ID:	SRG-OS-000075-GPOS-00043
# Finding Level:	medium
# 
# Rule Summary:
#	Passwords must be restricted to a 24 hours/1 day minimum lifetime.
#
# CCI-000198 
#    NIST SP 800-53 :: IA-5 (1) (d) 
#    NIST SP 800-53A :: IA-5 (1).1 (v) 
#    NIST SP 800-53 Revision 4 :: IA-5 (1) (d) 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-010240"
diag_out "   Passwords must be restricted to a 24"
diag_out "   hours/1 day minimum lifetime."
diag_out "----------------------------------------"
