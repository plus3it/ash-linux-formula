#!/bin/sh
# STIG ID:	RHEL-07-030310
# Rule ID:	SV-86709r2_rule
# Vuln ID:	V-72085
# SRG ID:	SRG-OS-000342-GPOS-00133
# Finding Level:	medium
# 
# Rule Summary:
#	The operating system must encrypt the transfer of audit records
#	off-loaded onto a different system or media from the system
#	being audited.
#
# CCI-001851 
#    NIST SP 800-53 Revision 4 :: AU-4 (1) 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-030310"
diag_out "   The operating system must encrypt"
diag_out "   the transfer of audit records"
diag_out "   off-loaded onto a different system"
diag_out "   or media from the system being"
diag_out "   audited."
diag_out "----------------------------------------"
