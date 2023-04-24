#!/bin/bash
#
# Ref Doc:    STIG - RHEL 8 v1r7
# Finding ID: V-244541
# Rule ID:    SV-244541r743872_rule
# STIG ID:    RHEL-08-020332
# SRG ID:     SRG-OS-000480-GPOS-00227
#
# Finding Level: high
#
# Rule Summary:
#       RHEL 8 must not allow blank or null passwords in the password-auth
#       file
#
# References:
#   CCI:
#     - CCI-000366
#   NIST SP 800-53: CM-6 b
#   NIST SP 800-53A: CM-6.1 (iv)
#   NIST SP 800-53 Rev 4: CM-6 b
#   NIST SP 800-53 Rev 5: CM-6 b
#
###########################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "--------------------------------------"
diag_out "STIG Finding ID: V-244541"
diag_out "     RHEL 8 must not allow blank or"
diag_out "     null passwords in the"
diag_out "     password-auth file"
diag_out "--------------------------------------"
diag_out ""
diag_out "changed=no"
