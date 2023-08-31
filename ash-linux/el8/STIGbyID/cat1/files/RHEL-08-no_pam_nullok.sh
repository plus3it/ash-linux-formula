#!/bin/bash

# Ref Doc:    STIG - RHEL 8 v1r11
# Finding ID: V-244540
#             V-244541
# Rule ID:    SV-244540r743869_rule
#             SV-244541r743872_rule
# STIG ID:    RHEL-08-020331
#             RHEL-08-020332
# SRG ID:     SRG-OS-000480-GPOS-00227
#
# Finding Level: high
#
# Rule Summary:
#       The OS must not allow blank or null passwords in either the system-auth
#       or password-auth files
#
# References:
#   CCI:
#     - CCI-000366
#       - NIST SP 800-53 :: CM-6 b
#       - NIST SP 800-53A :: CM-6.1 (iv)
#       - NIST SP 800-53 Revision 4 :: CM-6 b
#
###########################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "--------------------------------------"
diag_out "STIG Finding IDs: V-244540, V-244541"
diag_out "     The OS must not allow blank or"
diag_out "     null passwords"
diag_out "--------------------------------------"
