#!/bin/sh
# Finding ID:	RHEL-07-040030
# Version:	RHEL-07-040030_rule
# SRG ID:	SRG-OS-000066-GPOS-00034
# Finding Level:	medium
# 
# Rule Summary:
#	The operating system, for PKI-based authentication, must
#	validate certificates by performing RFC 5280-compliant
#	certification path validation.
#
# CCI-000185 
#    NIST SP 800-53 :: IA-5 (2) 
#    NIST SP 800-53A :: IA-5 (2).1 
#    NIST SP 800-53 Revision 4 :: IA-5 (2) (a) 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-040030"
diag_out "   The operating system, for PKI-based"
diag_out "   authentication, must validate"
diag_out "   certificates by performing RFC"
diag_out "   5280-compliant certification path"
diag_out "   validation."
diag_out "----------------------------------------"
