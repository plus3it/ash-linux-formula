#!/bin/sh
# STIG ID:	RHEL-07-010350
# Rule ID:	SV-86573r3_rule
# Vuln ID:	V-71949
# SRG ID:	SRG-OS-000373-GPOS-00156
# Finding Level:	medium
# 
# Rule Summary:
#	Users must re-authenticate for privilege escalation.
#
# CCI-002038 
#    NIST SP 800-53 Revision 4 :: IA-11 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-010350"
diag_out "   Users must re-authenticate for"
diag_out "   privilege escalation."
diag_out "----------------------------------------"
