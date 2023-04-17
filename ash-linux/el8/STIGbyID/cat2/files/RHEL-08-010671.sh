#!/bin/bash
#
# Ref Doc:    STIG - RHEL 8 v1r9
# Finding ID: V-230311
# Rule ID:    SV-230311r858769_rule
# STIG ID:    RHEL-08-010671
# SRG ID:     SRG-OS-000480-GPOS-00227
#
# Finding Level: medium
#
# Rule Summary:
#       RHEL 8 must disable the `kernel.core_pattern` setting
#
# References:
#   CCI:
#     - CCI-000366
#   NIST SP 800-53 :: CM-6 b
#   NIST SP 800-53A :: CM-6.1 (iv)
#   NIST SP 800-53 Revision 4 :: CM-6 b
#
###########################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "--------------------------------------"
diag_out "STIG Finding ID: V-230311"
diag_out "     The OS must disable the"
diag_out "     `kernel.core_pattern` setting"
diag_out "--------------------------------------"
