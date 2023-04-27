#!/bin/bash
#
# Ref Doc:    STIG - RHEL 8 v1r9
# Finding ID: V-230550
# Rule ID:    SV-230550r627750_rule
# STIG ID:    RHEL-08-040290
# SRG ID:     SRG-OS-000480-GPOS-00227
#
# Finding Level: medium
#
# Rule Summary:
#       The OS must be configured to prevent unrestricted mail relaying
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
diag_out "STIG Finding ID: V-230550"
diag_out "     OS must be configured to prevent"
diag_out "     unrestricted mail relaying"
diag_out "--------------------------------------"
