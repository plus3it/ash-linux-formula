#!/bin/bash
#
# STIG ID:	RHEL-07-010491
# Rule ID:	SV-95719r1_rule
# Vuln ID:	V-81007
# SRG ID:	SRG-OS-000080-GPOS-00048
# Finding Level:	high
#
# Rule Summary:
#	Systems using Unified Extensible Firmware Interface (UEFI)
#	must require authentication upon booting into single-user
#	and maintenance modes.
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
diag_out "STIG Finding ID: RHEL-07-010491"
diag_out "   Systems using Unified Extensible"
diag_out "   Firmware Interface (UEFI) must"
diag_out "   require authentication upon booting"
diag_out "   into single-user and maintenance"
diag_out "   modes."
diag_out "----------------------------------------"

