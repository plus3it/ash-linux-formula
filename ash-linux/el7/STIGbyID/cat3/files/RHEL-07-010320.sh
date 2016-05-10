#!/bin/sh
#
# STIG URL:
# Finding ID:	RHEL-07-010320
# Version:	RHEL-07-010320_rule
# SRG ID:	SRG-OS-000123-GPOS-00064
# Finding Level:	low
#
# Rule Summary:
#     The operating system must be configured such that emergency 
#     administrator accounts are never automatically removed or 
#     disabled.
#
# CCI-001682
#    NIST SP 800-53 :: AC-2 (2)
#    NIST SP 800-53A :: AC-2 (2).1 (ii)
#    NIST SP 800-53 Revision 4 :: AC-2 (2)
#
#################################################################

diag_out() {
   echo "${1}"
}

diag_out "---------------------------------------------"
diag_out "STIG Finding ID: RHEL-07-010320"
diag_out "   The operating system must be configured"
diag_out "   such that emergency administrator"
diag_out "   accounts are never automatically"
diag_out "   removed or disabled."
diag_out "---------------------------------------------"
