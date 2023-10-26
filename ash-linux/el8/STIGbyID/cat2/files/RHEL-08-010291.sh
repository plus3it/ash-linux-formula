#!/bin/bash
#
# Ref Doc:    STIG - RHEL 8 v1r11
# Finding ID: V-230252
# Rule ID:    SV-230252r917873_rule
# STIG ID:    RHEL-08-010291
# SRG ID:     SRG-OS-000250-GPOS-00093
#
# Finding Level: medium
#
# Rule Summary:
#       The operating system must implement DoD-approved encryption to protect
#       the confidentiality of SSH server connections
#
# References:
#   CCI:
#     - CCI-001453
#         NIST SP 800-53 :: AC-17 (2)
#         NIST SP 800-53A :: AC-17.1 (2).1
#         NIST SP 800-53 Revision 4 :: AC-17 (2)
#
###########################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "--------------------------------------"
diag_out "STIG Finding ID: V-230252"
diag_out "     The OS must allow only DoD-"
diag_out "     approved SSH encryption-ciphers"
diag_out "--------------------------------------"
