#!/bin/sh
# STIG ID:	RHEL-07-010060
# Rule ID:	SV-86515r6_rule
# Vuln ID:	V-71891
# SRG ID:	SRG-OS-000028-GPOS-00009
# Finding Level:	medium
# 
# Rule Summary:
#	The operating system must enable a user session lock until that
#	user re-establishes access using established identification and
#	authentication procedures.
#
# CCI-000056 
#    NIST SP 800-53 :: AC-11 b 
#    NIST SP 800-53A :: AC-11.1 (iii) 
#    NIST SP 800-53 Revision 4 :: AC-11 b 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-010060"
diag_out "   The operating system must enable a"
diag_out "   user session lock until that user"
diag_out "   reauthenticates."
diag_out "----------------------------------------"
