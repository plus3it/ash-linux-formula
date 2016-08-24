#!/bin/bash
#
# Finding ID:	RHEL-07-010020
# Version:	RHEL-07-010020_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	high
# 
# Rule Summary:
#	The cryptographic hash of system files and commands must
#	match vendor values.
#
# CCI-000663 
#    NIST SP 800-53 :: SA-7 
#    NIST SP 800-53A :: SA-7.1 (ii) 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-010020"
diag_out "   The cryptographic hash of system"
diag_out "   files and commands must match vendor"
diag_out "   values."
diag_out "----------------------------------------"

