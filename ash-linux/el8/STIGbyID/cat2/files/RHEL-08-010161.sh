#!/bin/bash
#
# Ref Doc:    STIG - RHEL 8 v1r9
# Finding ID: V-230238
# Rule ID:    SV-230238r646862_rule
# STIG ID:    RHEL-08-010161
# SRG ID:     SRG-OS-000120-GPOS-00061
#
# Finding Level: medium
#
# Rule Summary:
#       The operating system must prevent system daemons from using
#       Kerberos for authentication
#
# References:
#   CCI:
#     - CCI-000803
#   NIST SP 800-53 :: IA-7
#   NIST SP 800-53A :: IA-7.1
#   NIST SP 800-53 Revision 4 :: IA-7
#
###########################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "--------------------------------------"
diag_out "STIG Finding ID: V-248543"
diag_out "     The OS system must prevent system"
diag_out "     daemons from using Kerberos for"
diag_out "     authentication"
diag_out "--------------------------------------"
