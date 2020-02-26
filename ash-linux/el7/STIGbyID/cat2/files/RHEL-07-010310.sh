#!/bin/sh
# Finding ID:	RHEL-07-010310
# Version:	RHEL-07-010310_rule
# SRG ID:	SRG-OS-000118-GPOS-00060
# Finding Level:	medium
# 
# Rule Summary:
#	The operating system must disable account identifiers
#	(individuals, groups, roles, and devices) if the password
#	expires.
#
# CCI-000795 
#    NIST SP 800-53 :: IA-4 e 
#    NIST SP 800-53A :: IA-4.1 (iii) 
#    NIST SP 800-53 Revision 4 :: IA-4 e 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-010310"
diag_out "   The operating system must disable"
diag_out "   account identifiers (individuals,"
diag_out "   groups, roles, and devices) if the"
diag_out "   password expires."
diag_out "----------------------------------------"
