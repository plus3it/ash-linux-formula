#!/bin/sh
# Finding ID:	RHEL-07-040050
# Version:	RHEL-07-040050_rule
# SRG ID:	SRG-OS-000068-GPOS-00036
# Finding Level:	medium
# 
# Rule Summary:
#	The operating system must map the authenticated identity to the
#	user or group account for PKI-based authentication.
#
# CCI-000187 
#    NIST SP 800-53 :: IA-5 (2) 
#    NIST SP 800-53A :: IA-5 (2).1 
#    NIST SP 800-53 Revision 4 :: IA-5 (2) (c) 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-040050"
diag_out "   The operating system must map the"
diag_out "   authenticated identity to the user"
diag_out "   or group account for PKI-based"
diag_out "   authentication."
diag_out "----------------------------------------"
