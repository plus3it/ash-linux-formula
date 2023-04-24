#!/bin/bash
#
# Ref Doc:    STIG - RHEL 8 v1r7
# Finding ID: V-230287
# Rule ID:    SV-230287r743951_rule
# STIG ID:    RHEL-08-010490
# SRG ID:     SRG-OS-000480-GPOS-00227
#
# Finding Level: medium
#
# Rule Summary:
#       The SSH private host key files must have mode 0600 or
#       less permissive
#
# References:
#   CCI:
#     - CCI-001233
#   NIST SP 800-53 :: SI-2 (2)
#   NIST SP 800-53A :: SI-2 (2).1 (ii)
#   NIST SP 800-53 Revision 4 :: SI-2 (2)
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "--------------------------------------------------"
diag_out "STIG Finding ID: file_permissions_sshd_private_key"
diag_out "   All SSH private host-key files must be set to"
diag_out "   mode '0600'"
diag_out "--------------------------------------------------"
diag_out ""
diag_out "changed=no"
