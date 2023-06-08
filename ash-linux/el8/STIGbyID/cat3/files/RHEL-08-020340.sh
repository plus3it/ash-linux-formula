#!/bin/bash
#
# Ref Doc:    STIG - RHEL 8 v1r7
# Finding ID: V-230381
# Rule ID:    SV-230381r627750_rule
# STIG ID:    RHEL-08-020340
# SRG ID:     SRG-OS-000480-GPOS-00227
#
# Finding Level: low
#
# Rule Summary:
#       The OS must display the date and time of the last successful
#       account logon upon logon
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
diag_out "STIG Finding ID: V-230350"
diag_out "    The OS must display the date and"
diag_out "    time of the last successful"
diag_out "    account logon upon logon"
diag_out "--------------------------------------"
