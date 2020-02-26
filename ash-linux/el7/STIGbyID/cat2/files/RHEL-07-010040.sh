#!/bin/sh
# STIG ID:	RHEL-07-010040
# Rule ID:	SV-86485r4_rule
# Vuln ID:	V-71861
# SRG ID:	SRG-OS-000023-GPOS-00006
# Finding Level:	medium
# 
# Rule Summary:
#	The operating system must display the approved Standard
#	Mandatory DoD Notice and Consent Banner before granting local
#	or remote access to the system via a graphical user logon.
#
# CCI-000048 
#    NIST SP 800-53 :: AC-8 a 
#    NIST SP 800-53A :: AC-8.1 (ii) 
#    NIST SP 800-53 Revision 4 :: AC-8 a 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-010040"
diag_out "   Graphical login system must display"
diag_out "   the Standard Mandatory DoD notice and"
diag_out "   consent banner before granting access"
diag_out "   to the system."
diag_out "----------------------------------------"
