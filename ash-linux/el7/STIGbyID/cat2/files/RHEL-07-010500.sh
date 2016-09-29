#!/bin/sh
# Finding ID:	RHEL-07-010500
# Version:	RHEL-07-010500_rule
# SRG ID:	SRG-OS-000104-GPOS-00051
# Finding Level:	medium
# 
# Rule Summary:
#	The operating system must uniquely identify and must
#	authenticate organizational users (or processes acting on
#	behalf of organizational users) using multi-factor
#	authentication.
#
# CCI-000766 
#    NIST SP 800-53 :: IA-2 (2) 
#    NIST SP 800-53A :: IA-2 (2).1 
#    NIST SP 800-53 Revision 4 :: IA-2 (2) 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-010500"
diag_out "   The operating system must uniquely"
diag_out "   identify and must authenticate"
diag_out "   organizational users using multi-"
diag_out "   factor authentication."
diag_out "----------------------------------------"
