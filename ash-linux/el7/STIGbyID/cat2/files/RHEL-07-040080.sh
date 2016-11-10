#!/bin/sh
# Finding ID:	RHEL-07-040080
# Version:	RHEL-07-040080_rule
# SRG ID:	SRG-OS-000068-GPOS-00036
# Finding Level:	medium
# 
# Rule Summary:
#	The cn_map file must be group owned by root.
#
# CCI-000187 
#    NIST SP 800-53 :: IA-5 (2) 
#    NIST SP 800-53A :: IA-5 (2).1 
#    NIST SP 800-53 Revision 4 :: IA-5 (2) (c) 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-040080"
diag_out "   The cn_map file must be group owned"
diag_out "   by root."
diag_out "----------------------------------------"
