#!/bin/bash
#
# Ref Doc:    STIG - RHEL 7 v3r11
# Finding ID: V-204587
# Rule ID:    SV-204587r861072_rule
# STIG ID:    RHEL-07-040320
# SRG ID:     SRG-OS-000163-GPOS-00072
#
# Finding Level: medium
#
# Rule Summary:
#       The Red Hat Enterprise Linux operating system must be configured
#       so that all network connections associated with SSH traffic are
#       terminated at the end of the session or after 10 minutes of
#       inactivity, except to fulfill documented and validated mission
#       requirements.
#
# References:
#   CCI:
#     - CCI-001133
#       - NIST SP 800-53 :: SC-10
#       - NIST SP 800-53A :: SC-10.1 (ii)
#       - NIST SP 800-53 Revision 4 :: SC-10
#     - CCI-002361
#       - NIST SP 800-53 Revision 4 :: AC-12
#
###########################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-040320"
diag_out "   All idles SSH sessions must be"
diag_out "   terminated after 10 minutes"
diag_out "----------------------------------------"
