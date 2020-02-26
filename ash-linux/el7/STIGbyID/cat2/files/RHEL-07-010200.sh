#!/bin/sh
# Finding ID:	RHEL-07-010200
# Version:	RHEL-07-010200_rule
# SRG ID:	SRG-OS-000073-GPOS-00041
# Finding Level:	medium
# 
# Rule Summary:
#	The PAM system service must be configured to store only
#	encrypted representations of passwords.
#
# CCI-000196 
#    NIST SP 800-53 :: IA-5 (1) (c) 
#    NIST SP 800-53A :: IA-5 (1).1 (v) 
#    NIST SP 800-53 Revision 4 :: IA-5 (1) (c) 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-010200"
diag_out "   The PAM system service must be"
diag_out "   configured to store only encrypted"
diag_out "   representations of passwords."
diag_out "----------------------------------------"
