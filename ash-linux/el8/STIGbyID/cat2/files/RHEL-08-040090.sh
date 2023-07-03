#!/bin/bash
# Ref Doc:    STIG - RHEL 8 v1r10
# Finding ID: V-230238
# Rule ID:    SV-230504r854047_rule
# STIG ID:    RHEL-08-040090
# SRG ID:     SRG-OS-000297-GPOS-00115
#
# Finding Level: medium
#
# Rule Summary:
#       The operating system must enable a firewall service that  employs
#       a deny-all, allow-by-exception policy for allowing connections to
#       other systems.
#
# References:
#   CCI:
#     - CCI-002314
#   NIST SP 800-53 Revision 4 :: AC-17 (1)
#
###########################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "--------------------------------------"
diag_out "STIG Finding ID: V-230238"
diag_out "     The OS activate a host-based"
diag_out "     firewall service with a default"
diag_out "     'deny-all' posture"
diag_out "--------------------------------------"
