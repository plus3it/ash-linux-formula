#!/bin/sh
# Finding ID:	RHEL-07-010230
# Version:	RHEL-07-010230_rule
# SRG ID:	SRG-OS-000075-GPOS-00043
# Finding Level:	medium
# 
# Rule Summary:
#	Passwords for new users must be restricted to a 24 hours/1 day
#	minimum lifetime.
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
diag_out "STIG Finding ID: RHEL-07-010230"
diag_out "   Passwords for new users must be"
diag_out "   restricted to a 24 hours/1 day"
diag_out "   minimum lifetime."
diag_out "----------------------------------------"
