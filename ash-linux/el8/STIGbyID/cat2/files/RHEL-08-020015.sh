#!/bin/bash
#
# Ref Doc:    STIG - RHEL 8 v1r7
# Finding ID: V-230337
# Rule ID:    SV-230337r743972_rule
# STIG ID:    RHEL-08-020015
# SRG ID:     SRG-OS-000021-GPOS-00005
#
# Finding Level: medium
#
# Rule Summary:
#       The OS must automatically lock an account until the locked account
#       is released by an administrator when three unsuccessful logon
#       attempts occur during a 15-minute time period.
#
# References:
#   CCI:
#     - CCI-000044
#
# NIST SP 800-53 :: AC-7 a
# NIST SP 800-53A :: AC-7.1 (ii)
# NIST SP 800-53 Revision 4 :: AC-7 a
#
###########################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "--------------------------------------"
diag_out "STIG Finding ID: V-230337"
diag_out "     The OS must require the system"
diag_out "     administrator intervention when"
diag_out "     accounts have been automatically"
diag_out "     locked out"
diag_out "--------------------------------------"
