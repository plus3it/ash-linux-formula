#!/bin/bash
#
# Finding ID:	RHEL-07-020300
# Version:	RHEL-07-020300_rule
# SRG ID:	SRG-OS-000104-GPOS-00051
# Finding Level:	low
# 
# Rule Summary:
#	All Group Identifiers (GIDs) referenced in the 
#	/etc/passwd file must be defined in the /etc/group file.
#
# CCI-000764 
#    NIST SP 800-53 :: IA-2 
#    NIST SP 800-53A :: IA-2.1 
#    NIST SP 800-53 Revision 4 :: IA-2 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-020300"
diag_out "   All Group Identifiers (GIDs)"
diag_out "   referenced in the /etc/passwd file"
diag_out "   must be defined in the /etc/group"
diag_out "   file."
diag_out "----------------------------------------"
