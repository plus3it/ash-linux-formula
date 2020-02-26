#!/bin/bash
#
# STIG ID:	RHEL-07-010440
# Rule ID:	SV-86577r2_rule
# Vuln ID:	V-71953
# SRG ID:	SRG-OS-000480-GPOS-00229
# Finding Level:	high
# 
# Rule Summary:
#	The operating system must not allow an unattended or 
#	automatic logon to the system via a graphical user interface.
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
diag_out "STIG Finding ID: RHEL-07-010440"
diag_out "   The operating system must not allow"
diag_out "   an unattended or automatic logon to"
diag_out "   the system via a graphical user"
diag_out "   interface."
diag_out "----------------------------------------"

