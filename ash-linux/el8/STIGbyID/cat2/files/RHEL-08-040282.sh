#!/bin/bash
#
# Ref Doc:    STIG - RHEL 8 v1r9
# Finding ID: V-230546
# Rule ID:    SV-230546r858824_rule
# STIG ID:    RHEL-08-040282
# SRG ID:     SRG-OS-000480-GPOS-00227
#
# Finding Level: medium
#
# Rule Summary:
#       The OS must restrict usage of ptrace to descendant processes.
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
diag_out "     The OS must restrict usage of the"
diag_out "     ptrace utility to descendant"
diag_out "     processes."
diag_out "--------------------------------------"
diag_out ""
diag_out "changed=no"
