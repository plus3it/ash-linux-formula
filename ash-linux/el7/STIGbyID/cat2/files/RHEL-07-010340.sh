#!/bin/sh
# STIG ID:	RHEL-07-010340
# Rule ID:	SV-86571r3_rule
# Vuln ID:	V-71947
# SRG ID:	SRG-OS-000373-GPOS-00156
# Finding Level:	medium
# 
# Rule Summary:
#	Users must provide a password for privilege escalation.
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
diag_out "STIG Finding ID: RHEL-07-010340"
diag_out "   Users must provide a password for"
diag_out "   privilege escalation."
diag_out "----------------------------------------"
