#!/bin/bash
#
# Finding ID:	RHEL-07-040010
# Version:	RHEL-07-040010_rule
# SRG ID:	SRG-OS-000027-GPOS-00008
# Finding Level:	low
# 
# Rule Summary:
#	The operating system must limit the number of concurrent
#	sessions to 10 for all accounts and/or account types.
#
# CCI-000054 
#    NIST SP 800-53 :: AC-10 
#    NIST SP 800-53A :: AC-10.1 (ii) 
#    NIST SP 800-53 Revision 4 :: AC-10 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-040010"
diag_out "   The operating system must limit the"
diag_out "   number of concurrent sessions to 10"
diag_out "   for all accounts and/or account"
diag_out "   types."
diag_out "----------------------------------------"
