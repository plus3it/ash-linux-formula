#!/bin/bash
#
# Ref Doc:    STIG - RHEL 8 v1r9
# Finding ID: V-230485
# Rule ID:    SV-230485r627750_rule
# STIG ID:    RHEL-08-030741
# SRG ID:     SRG-OS-000095-GPOS-00049
#
# Finding Level: low
#
# Rule Summary:
#       The OS must disable the chrony daemon from acting as a server.
#
# References:
#   CCI:
#     - CCI-000381
#   NIST SP 800-53 :: CM-7
#   NIST SP 800-53A :: CM-7.1 (ii)
#   NIST SP 800-53 Revision 4 :: CM-7 a
#
###########################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "--------------------------------------"
diag_out "STIG Finding ID: V-230485"
diag_out "    The OS must disable the chrony"
diag_out "    daemon from acting as a server"
diag_out "--------------------------------------"
diag_out ""
diag_out "changed=no"
