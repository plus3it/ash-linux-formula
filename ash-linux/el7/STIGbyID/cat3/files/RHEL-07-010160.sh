#!/bin/sh
#
# STIG URL:
# Finding ID:	RHEL-07-010160
# Version:	RHEL-07-010160_rule
# SRG ID:	SRG-OS-000072-GPOS-0040
# Finding Level:	low
#
# Rule Summary:
#     When passwords are changed the number of repeating characters of 
#     the same character class must not be more than two characters.
#
# CCI-000195
#    NIST SP 800-53 :: IA-5 (1) (b)
#    NIST SP 800-53A :: IA-5 (1).1 (v)
#    NIST SP 800-53 Revision 4 :: IA-5 (1) (b)
#
#################################################################

diag_out() {
   echo "${1}"
}

diag_out "---------------------------------------------"
diag_out "STIG Finding ID: RHEL-07-010160"
diag_out "   Configure the operating system to require"
diag_out "   new/reset passwords to contain no more "
diag_out "   than two, consecutive characters of the"
diag_out "   same character-class."
diag_out "---------------------------------------------"
