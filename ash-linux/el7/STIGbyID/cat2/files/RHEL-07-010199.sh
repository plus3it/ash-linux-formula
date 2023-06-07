#!/bin/bash
#
# Ref Doc:    STIG - RHEL 7 v3r11
# Finding ID: V-255928
# Rule ID:    SV-255928r902706_rule
# STIG ID:    RHEL-07-010199
# SRG ID:     SRG-OS-000073-GPOS-00041
#
# Finding Level: medium
#
# Rule Summary:
#       The operating system must be configured to prevent overwriting of
#       custom authentication configuration settings by the authconfig
#       utility.
#
# References:
#   CCI:
#     - CCI-000196
#       - NIST SP 800-53 :: IA-5 (1) (c)
#       - NIST SP 800-53A :: IA-5 (1).1 (v)
#       - NIST SP 800-53 Revision 4 :: IA-5 (1) (c)
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-010199"
diag_out "   The OS must be configured to prevent"
diag_out "   overwriting of PAM files by the"
diag_out "   authconfig utility"
diag_out "----------------------------------------"
