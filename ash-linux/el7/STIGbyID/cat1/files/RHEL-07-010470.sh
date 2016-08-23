#!/bin/bash
#
# Finding ID:	RHEL-07-010470
# Version:	RHEL-07-010470_rule
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
diag_out "STIG Finding ID: RHEL-07-010470"
diag_out "----------------------------------------"

