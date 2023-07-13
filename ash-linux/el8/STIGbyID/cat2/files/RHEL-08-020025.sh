#!/bin/bash
# Ref Doc:    STIG - RHEL 8 v1r10
# Finding ID: V-244533
# Rule ID:    SV-244533r743848_rule
# STIG ID:    RHEL-08-020025
# SRG ID:     SRG-OS-000021-GPOS-00005
#             SRG-OS-000329-GPOS-00128
#
# Finding Level: medium
#
# Rule Summary:
#       The OS must configure the use of the pam_faillock.so module in the
#       /etc/pam.d/system-auth file.
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
diag_out "STIG Finding ID: V-244533"
diag_out "     OS must configure pam_faillock"
diag_out "     module before pam_unix in the"
diag_out "     /etc/pam.d/system-auth file"
diag_out "--------------------------------------"
