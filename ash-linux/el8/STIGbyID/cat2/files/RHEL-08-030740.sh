#!/bin/bash
#
# Ref Doc:    STIG - RHEL 8 v1r7
# Finding ID: V-230484
# Rule ID:    SV-230484r627750_rule
# STIG ID:    RHEL-08-030740
# SRG ID:     SRG-OS-000355-GPOS-00143
#
# Finding Level: medium
#
# Rule Summary:
#       If using NTP, the operating system must be configured to use
#       `server` directives instead of `pool` directives
#
# References:
#   CCI:
#     - CCI-001891
#   NIST SP 800-53 Revision 4 :: AU-8 (1) (a)
#
###########################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "--------------------------------------"
diag_out "STIG Finding ID: V-230484"
diag_out "     Use server directives when using"
diag_out "     chronyd for time-synchronization"
diag_out "--------------------------------------"
