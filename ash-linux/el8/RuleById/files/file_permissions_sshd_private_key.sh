#!/bin/sh
#
# Versions:
#   - file_permissions_sshd_private_key
# SRG ID:
#   - SRG-OS-000480-GPOS-00227
# Finding Level:        medium
#
# Rule Summary:
#       All SSH private host-key files must be set to mode '0600'
#
# Identifiers:
#
# References:
#   - CCI-000366
#   - CIP-003-8 R5.1.1
#   - CIP-003-8 R5.3
#   - CIP-004-6 R2.3
#   - CIP-007-3 R2.1
#   - CIP-007-3 R2.2
#   - CIP-007-3 R2.3
#   - CIP-007-3 R5.1
#   - CIP-007-3 R5.1.1
#   - CIP-007-3 R5.1.2
#   - AC-17(a)
#   - CM-6(a)
#   - AC-6(1)
#   - SV-248602r779372_rule
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "--------------------------------------------------"
diag_out "STIG Finding ID: file_permissions_sshd_private_key"
diag_out "   All SSH private host-key files must be set to"
diag_out "   mode '0600'"
diag_out "--------------------------------------------------"

