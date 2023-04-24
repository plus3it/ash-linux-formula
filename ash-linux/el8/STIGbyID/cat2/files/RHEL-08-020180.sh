#!/bin/bash
#
# Ref Doc:    STIG - RHEL 8 v1r9
# Finding ID: V-230364
# Rule ID:    SV-230364r627750_rule
# STIG ID:    RHEL-08-020180
# SRG ID:     SRG-OS-000075-GPOS-00043
#
# Finding Level: medium
#
# Rule Summary:
#       Passwords managed by the operating system  must have a 24 hours/1
#       day minimum password lifetime restriction in /etc/shadow.
#
# References:
#   CCI:
#     - CCI-000198
#   NIST SP 800-53 :: IA-5 (1) (d)
#   NIST SP 800-53A :: IA-5 (1).1 (v)
#   NIST SP 800-53 Revision 4 :: IA-5 (1) (d)
#
###########################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "--------------------------------------"
diag_out "STIG Finding ID: V-230364"
diag_out "     OS-/locally-managed passwords may"
diag_out "     not be changed more than once per"
diag_out "     twenty-four hours"
diag_out "--------------------------------------"
diag_out ""
diag_out "changed=no"
