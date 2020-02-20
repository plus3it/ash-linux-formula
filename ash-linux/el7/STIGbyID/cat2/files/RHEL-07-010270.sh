#!/bin/sh
# STIG ID:	RHEL-07-010270
# Rule ID:	SV-86557r3_rule
# Vuln ID:	V-71933
# SRG ID:	SRG-OS-000077-GPOS-00045
# Finding Level:	medium
# 
# Rule Summary:
#	Passwords must be prohibited from reuse for a minimum of
#       five generations.
#
# CCI-000200 
#    NIST SP 800-53 :: IA-5 (1) (e) 
#    NIST SP 800-53A :: IA-5 (1).1 (v) 
#    NIST SP 800-53 Revision 4 :: IA-5 (1) (e) 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-010270"
diag_out "   Passwords must be prohibited from"
diag_out "   reuse for a minimum of five"
diag_out "   generations."
diag_out "----------------------------------------"
