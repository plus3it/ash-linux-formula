#!/bin/sh
# Finding ID:	RHEL-07-020130
# Version:	RHEL-07-020130_rule
# SRG ID:	SRG-OS-000363-GPOS-00150
# Finding Level:	medium
# 
# Rule Summary:
#	A file integrity tool must verify the baseline operating system
#	configuration at least weekly.
#
# CCI-001744 
#    NIST SP 800-53 Revision 4 :: CM-3 (5) 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-020130"
diag_out "   A file integrity tool must verify"
diag_out "   the baseline operating system"
diag_out "   configuration at least weekly."
diag_out "----------------------------------------"
