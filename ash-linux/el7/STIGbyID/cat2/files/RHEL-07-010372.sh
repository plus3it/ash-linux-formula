#!/bin/sh
# Finding ID:	RHEL-07-010372
# Version:	RHEL-07-010372_rule
# SRG ID:	SRG-OS-000329-GPOS-00128
# Finding Level:	medium
# 
# Rule Summary:
#	Accounts subject to three unsuccessful login attempts within
#	15 minutes must be locked for the maximum configurable period.
#
# CCI-002238 
#    NIST SP 800-53 Revision 4 :: AC-7 b 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-010372"
diag_out "   Accounts subject to three"
diag_out "   unsuccessful login attempts within"
diag_out "   15 minutes must be locked for the"
diag_out "   maximum configurable period."
diag_out "----------------------------------------"
