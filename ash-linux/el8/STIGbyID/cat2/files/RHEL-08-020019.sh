#!/bin/bash
#
# Ref Doc:    STIG - RHEL 8 v1r9
# Finding ID: V-230341
# Rule ID:    SV-230341r743978_rule
# STIG ID:    RHEL-08-020019
# SRG ID:     SRG-OS-000021-GPOS-00005
#
# Finding Level: medium
#
# Rule Summary:
#       The operating system must prevent system messages from being
#       presented when three unsuccessful logon attempts occur.
#
# References:
#   CCI:
#     - CCI-000044
#   NIST SP 800-53 :: AC-7 a
#   NIST SP 800-53A :: AC-7.1 (ii)
#   NIST SP 800-53 Revision 4 :: AC-7 a
#
###########################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "--------------------------------------"
diag_out "STIG Finding ID: V-230341"
diag_out "     The OS must not print system"
diag_out "     messages after three failed login"
diag_out "     attempts"
diag_out "--------------------------------------"
diag_out ""
diag_out "changed=no"
