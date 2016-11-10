#!/bin/sh
# Finding ID:	RHEL-07-040040
# Version:	RHEL-07-040040_rule
# SRG ID:	SRG-OS-000067-GPOS-00035
# Finding Level:	medium
# 
# Rule Summary:
#	The operating system, for PKI-based authentication, must
#	enforce authorized access to all PKI private keys stored or
#	used by the operating system.
#
# CCI-000186 
#    NIST SP 800-53 :: IA-5 (2) 
#    NIST SP 800-53A :: IA-5 (2).1 
#    NIST SP 800-53 Revision 4 :: IA-5 (2) 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-040040"
diag_out "   The operating system, for PKI-based"
diag_out "   authentication, must enforce"
diag_out "   authorized access to all PKI private"
diag_out "   keys stored or used by the operating"
diag_out "   system."
diag_out "----------------------------------------"
