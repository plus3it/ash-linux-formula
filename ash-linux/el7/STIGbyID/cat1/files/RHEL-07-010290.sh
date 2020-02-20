#!/bin/bash
#
# STIG ID:	RHEL-07-010290
# Rule ID:	SV-86561r3_rule
# Vuln ID:	V-71937
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	high
#
# Rule Summary:
#	The system must not have accounts configured with blank or
#	null passwords.
#
# CCI-000366
#    NIST SP 800-53 :: CM-6 b
#    NIST SP 800-53A :: CM-6.1 (iv)
#    NIST SP 800-53 Revision 4 :: CM-6 b
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-010290"
diag_out "   The system must not have accounts"
diag_out "   configured with blank or null"
diag_out "   passwords."
diag_out "----------------------------------------"

