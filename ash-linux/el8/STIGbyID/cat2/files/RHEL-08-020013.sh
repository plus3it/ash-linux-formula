#!/bin/bash
#
# Ref Doc:    STIG - RHEL 8 v1r7
# Finding ID: V-230335
# Rule ID:    SV-230335r743969_rule
# STIG ID:    RHEL-08-020013
# SRG ID:     SRG-OS-000021-GPOS-00005
#
# Finding Level: medium
#
# Rule Summary:
#       RHEL 8 must automatically lock an account when three unsuccessful
#       logon attempts occur within a 15-minute time period.
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
diag_out "STIG Finding ID: V-230333"
diag_out "     The OS must automatically lock an"
diag_out "     account when three unsuccessful"
diag_out "     logon attempts within 15 minutes"
diag_out "--------------------------------------"
