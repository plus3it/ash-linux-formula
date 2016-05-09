#!/bin/sh
#
# STIG URL:
# Finding ID:	RHEL-07-040010
# Version:	RHEL-07-040010_rule
# SRG ID:	
# Finding Level:	low
#
# Rule Summary:
#     The operating system must limit the number of concurrent 
#     sessions to ten for all accounts and/or account types.
#
# CCI-000054
#    NIST SP 800-53 :: AC-10
#    NIST SP 800-53A :: AC-10.1 (ii)
#    NIST SP 800-53 Revision 4 :: AC-10
#
#################################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: RHEL-07-040010"
diag_out "  The system should limit users"
diag_out "  to no more than 10 simultaneous"
diag_out "  system logins"
diag_out "----------------------------------"

