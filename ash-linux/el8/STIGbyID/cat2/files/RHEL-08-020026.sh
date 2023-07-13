#!/bin/bash
# Ref Doc:    STIG - RHEL 8 v1r10
# Finding ID: V-244534
# Rule ID:    SV-244534r743851_rule
# STIG ID:    RHEL-08-020026
# SRG ID:     SRG-OS-000021-GPOS-00005
#             SRG-OS-000329-GPOS-00128
#
# Finding Level: medium
#
# Rule Summary:
#       The OS must configure the use of the pam_faillock.so module in the
#       /etc/pam.d/password-auth file.
#
# References:
#   CCI:
#     - CCI-000044
#       - NIST SP 800-53 :: AC-7 a
#       - NIST SP 800-53A :: AC-7.1 (ii)
#       - NIST SP 800-53 Revision 4 :: AC-7 a
#
###########################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "--------------------------------------"
diag_out "STIG Finding ID: V-244534"
diag_out "     OS must use pam_faillock.so in"
diag_out "     the /etc/pam.d/password-auth file"
diag_out "--------------------------------------"
