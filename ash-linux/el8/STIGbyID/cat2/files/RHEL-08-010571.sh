#!/bin/bash
#
# Ref Doc:    STIG - RHEL 8 v1r7
# Finding ID: V-230300
# Rule ID:    SV-230300r743959_rule
# STIG ID:    RHEL-08-010571
# SRG ID:     SRG-OS-000480-GPOS-00227
#
# Finding Level: medium
#
# Rule Summary:
#       The OS must prevent files with the setuid and setgid bit set from
#       being executed on the /boot directory
#
# References:
#   CCI:
#     - CCI-000366
#
# NIST SP 800-53 :: CM-6 b
# NIST SP 800-53A :: CM-6.1 (iv)
# NIST SP 800-53 Revision 4 :: CM-6 b
#
###########################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "--------------------------------------"
diag_out "STIG Finding ID: V-230300"
diag_out "     The setuid attribute must be set"
diag_out "     on the /boot mount-point"
diag_out "--------------------------------------"
diag_out ""
diag_out "changed=no"
