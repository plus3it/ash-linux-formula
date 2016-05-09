#!/bin/sh
#
# STIG URL:
# Finding ID:	RHEL-07-010000
# Version:	RHEL-07-010000_rule
# SRG ID:	SRG-OS-000001-GPOS-00001
# Finding Level:	low
#
# Rule Summary:
#     The operating system must provide automated mechanisms for 
#     supporting account management functions.
#
# CCI-000015
#    NIST SP 800-53 :: AC-2 (1)
#    NIST SP 800-53A :: AC-2 (1).1
#    NIST SP 800-53 Revision 4 :: AC-2 (1)
#
#################################################################

diag_out() {
   echo "${1}"
}

diag_out "---------------------------------------------"
diag_out "STIG Finding ID: RHEL-07-010000"
diag_out "   Verify whether the operating system is"
diag_out "   using the operating System Security"
diag_out "   Services Daemon (SSSD) for identity and"
diag_out "   authentication services."
diag_out "---------------------------------------------"
