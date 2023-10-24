#!/bin/bash
#
# Ref Doc:    STIG - RHEL 8 v1r11
# Finding ID: V-244525
# Rule ID:    SV-244525r917886_rule
# STIG ID:    RHEL-08-010201
# SRG ID:     SRG-OS-000163-GPOS-00072
#             SRG-OS-000126-GPOS-00066
#             SRG-OS-000279-GPOS-00109
#
# Finding Level: medium
#
# Rule Summary:
#       RHEL 8 be configured so that all network connections associated with SSH
#       traffic are terminated after 10 minutes of becoming unresponsive.
#
# References:
#   CCI:
#     - CCI-001133
#   NIST SP 800-53 :: SC-10
#   NIST SP 800-53A :: SC-10.1 (ii)
#   NIST SP 800-53 Revision 4 :: SC-10
#
###########################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "--------------------------------------"
diag_out "STIG Finding ID: V-244525"
diag_out "     The OS must terminate all SSH"
diag_out "     sessions ater 10 minutes of"
diag_out "     becoming unresponsive"
diag_out "--------------------------------------"
