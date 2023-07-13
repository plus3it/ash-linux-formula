#!/bin/bash
# Ref Doc:    STIG - RHEL 8 v1r10
# Finding ID: V-230532
# Rule ID:    SV-230532r627750_rule
# STIG ID:    RHEL-08-040180
# SRG ID:     <none>
#
# Finding Level: medium
#
# Rule Summary:
#       The debug-shell systemd service must be disabled.
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
diag_out "STIG Finding ID: V-230532"
diag_out "     The debug-shell systemd service"
diag_out "     must be disabled."
diag_out "--------------------------------------"
