#!/bin/bash
#
# Ref Doc:    STIG - RHEL 8 v1r12
# Finding ID: V-257258
# Rule ID:    SV-257258r917891_rule
# STIG ID:    RHEL-08-020035
# SRG ID:     SRG-OS-000163-GPOS-00072
#
# Finding Level: medium
#
# Rule Summary:
#       The Operating System must terminate idle user sessions
#
# References:
#   CCI:
#     - CCI-001133
#   NIST SP 800-53 :: SC-10
#   NIST SP 800-53A :: SC-10.1 (ii)
#   NIST SP 800-53 Revision 4 :: SC-10
#
###########################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "--------------------------------------"
diag_out "STIG Finding ID: V-257258"
diag_out "     The OS must terminate idle user"
diag_out "     sessions"
diag_out "--------------------------------------"
