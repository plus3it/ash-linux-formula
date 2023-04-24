#!/bin/bash
#
# Ref Doc:    STIG - RHEL 8 v1r9
# Finding ID: V-230348
# Rule ID:    SV-230348r880720_rule
# STIG ID:    RHEL-08-020040
# SRG ID:     SRG-OS-000028-GPOS-00009
#             SRG-OS-000030-GPOS-00011
#
# Finding Level: medium
#
# Rule Summary:
#       The operating system must enable a user session lock until that
#       user re-establishes access using established identification and
#       authentication procedures for command line sessions.
#
# References:
#   CCI:
#     - CCI-000056
#   NIST SP 800-53 :: AC-11 b
#   NIST SP 800-53A :: AC-11.1 (iii)
#   NIST SP 800-53 Revision 4 :: AC-11 b
#
###########################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "--------------------------------------"
diag_out "STIG Finding ID: V-230348"
diag_out "     The OS must lock user sessions"
diag_out "     until user re-authenticates"
diag_out "--------------------------------------"
diag_out ""
diag_out "changed=no"
