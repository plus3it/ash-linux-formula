#!/bin/sh
#
# STIG URL:
# Finding ID:	RHEL-07-020300
# Version:	RHEL-07-020300_rule
# SRG ID:	
# Finding Level:	low
#
# Rule Summary:
#     All GIDs referenced in the /etc/passwd file must be defined in 
#     the /etc/group file.
#
# CCI-000764
#    NIST SP 800-53 :: IA-2
#    NIST SP 800-53A :: IA-2.1
#    NIST SP 800-53 Revision 4 :: IA-2
#
#################################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: RHEL-07-020300"
diag_out "   All GIDs referenced in the"
diag_out "   /etc/passwd file should have a"
diag_out "   matching reference in the"
diag_out "   /etc/group file."
diag_out "----------------------------------"

