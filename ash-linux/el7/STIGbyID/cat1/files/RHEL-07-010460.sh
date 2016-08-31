#!/bin/bash
#
# Finding ID:	RHEL-07-010460
# Version:	RHEL-07-010460_rule
# SRG ID:	SRG-OS-000080-GPOS-00048
# Finding Level:	high
#
# Rule Summary:
#	Systems with a Basic Input/Output System (BIOS) must
#	require authentication upon booting into single-user and
#	maintenance modes.
#
# CCI-000213
#    NIST SP 800-53 :: AC-3
#    NIST SP 800-53A :: AC-3.1
#    NIST SP 800-53 Revision 4 :: AC-3
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-010460"
diag_out "   Systems with a Basic Input/Output"
diag_out "   System (BIOS) must require"
diag_out "   authentication upon booting into"
diag_out "   single-user and maintenance modes."
diag_out "----------------------------------------"

