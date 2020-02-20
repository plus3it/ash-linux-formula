#!/bin/bash
#
# STIG ID:	RHEL-07-010300
# Rule ID:	SV-86563r3_rule
# Vuln ID:	V-71939
# SRG ID:	SRG-OS-000106-GPOS-00053
# Finding Level:	high
#
# Rule Summary:
#	The SSH daemon must not allow authentication using an empty
#	password.
#
# CCI-000766
#    NIST SP 800-53 :: IA-2 (2)
#    NIST SP 800-53A :: IA-2 (2).1
#    NIST SP 800-53 Revision 4 :: IA-2 (2)
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-010300"
diag_out "   The SSH daemon must not allow"
diag_out "   authentication using an empty"
diag_out "   password."
diag_out "----------------------------------------"

