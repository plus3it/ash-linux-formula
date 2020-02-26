#!/bin/sh
# Finding ID:	RHEL-07-010250
# Version:	RHEL-07-010250_rule
# SRG ID:	SRG-OS-000076-GPOS-00044
# Finding Level:	medium
# 
# Rule Summary:
#	Passwords for new users must be restricted to a 60-day
#       maximum lifetime.
#
# CCI-000199 
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
diag_out "STIG Finding ID: RHEL-07-010250"
diag_out "   Passwords for new users must be"
diag_out "   restricted to a 60-day maximum"
diag_out "   lifetime."
diag_out "----------------------------------------"
