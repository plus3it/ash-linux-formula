#!/bin/sh
# Ref Doc:    STIG - RHEL 7 v3r11
# Finding ID: V-250314
# Rule ID:    SV-250314r877392_rule
# STIG ID:    RHEL-07-020023
# SRG ID:     SRG-OS-000324-GPOS-00125
#
# Finding Level: medium
#
# Rule Summary:
#       The operating system must elevate the SELinux context when an
#       administrator calls the sudo command
#
# References:
#   CCI:
#     - CCI-002165
#       - NIST SP 800-53 Revision 4 :: AC-3 (4)
#     - CCI-002235
#       - NIST SP 800-53 Revision 4 :: AC-6 (10)
#
###########################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-020023"
diag_out "     The OS must elevate the SELinux" 
diag_out "     context when admin users call the"
diag_out "     sudo command"
diag_out "----------------------------------------"
