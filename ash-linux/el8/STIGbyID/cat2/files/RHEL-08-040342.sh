#!/bin/bash
#
# Ref Doc:    STIG - RHEL 8 v1r12
# Finding ID: V-255924
# Rule ID:    SV-255924r917888_rule
# STIG ID:    RHEL-08-040342
# SRG ID:     SRG-OS-000250-GPOS-00093
#
# Finding Level: medium
#
# Rule Summary:
#       The SSH server must be configured to use only FIPS-validated key
#       exchange algorithms.
#
# References:
#   CCI:
#     - CCI-001453
#         NIST SP 800-53 :: AC-17 (2)
#         NIST SP 800-53A :: AC-17.1 (2).1
#         NIST SP 800-53 Revision 4 :: AC-17 (2)
#
###########################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "--------------------------------------"
diag_out "STIG Finding ID: V-248543"
diag_out "     The SSH daemon must allow only"
diag_out "     FIPS-validated key-exchange"
diag_out "     algorithms"
diag_out "--------------------------------------"
