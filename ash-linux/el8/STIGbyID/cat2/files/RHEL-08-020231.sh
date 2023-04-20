#!/bin/bash
#
# Ref Doc:    STIG - RHEL 8 v1r9
# Finding ID: V-230370
# Rule ID:    SV-230370r627750_rule
# STIG ID:    RHEL-08-020231
# SRG ID:     SRG-OS-000078-GPOS-00046
#
# Finding Level: medium
#
# Rule Summary:
#       Passwords for new users must have a minimum of 15 characters
#
# References:
#   CCI:
#     - CCI-000205
#   NIST SP 800-53 :: IA-5 (1) (a)
#   NIST SP 800-53A :: IA-5 (1).1 (i)
#   NIST SP 800-53 Revision 4 :: IA-5 (1) (a)
#
###########################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "--------------------------------------"
diag_out "STIG Finding ID: V-245540"
diag_out "     Passwords for new users must have"
diag_out "     a minimum of 15 characters"
diag_out "--------------------------------------"
diag_out ""
diag_out "changed=no"
