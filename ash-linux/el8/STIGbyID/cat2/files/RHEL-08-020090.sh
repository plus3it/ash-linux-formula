#!/bin/bash
#
# Ref Doc:    STIG - RHEL 8 v1r7
# Finding ID: V-230355
# Rule ID:    SV-230355r818836_rule
# STIG ID:    RHEL-08-020090
# SRG ID:     SRG-OS-000068-GPOS-00036
#
# Finding Level: medium
#
# Rule Summary:
#       RHEL 8 must map the authenticated identity to the user or group
#       account for PKI-based authentication
#
# References:
#   CCI:
#     - CCI-000187
#   NIST SP 800-53 :: IA-5 (2)
#   NIST SP 800-53A :: IA-5 (2).1
#   NIST SP 800-53 Revision 4 :: IA-5 (2) (c)
#
###########################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "--------------------------------------"
diag_out "STIG Finding ID: V-230355"
diag_out "     The OS must map PKI entity to"
diag_out "     the POSIX user or group account"
diag_out "--------------------------------------"
