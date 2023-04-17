#!/bin/bash
#
# Ref Doc:    STIG - RHEL 8 v1r9
# Finding ID: V-230343
# Rule ID:    SV-230343r743981_rule
# STIG ID:    RHEL-08-020021
# SRG ID:     SRG-OS-000021-GPOS-00005
#
# Finding Level: medium
#
# Rule Summary:
#       The operating system must log user name information when
#       unsuccessful logon attempts occur.
#
# References:
#   CCI:
#     - CCI-000044
#   NIST SP 800-53 :: AC-7 a
#   NIST SP 800-53A :: AC-7.1 (ii)
#   NIST SP 800-53 Revision 4 :: AC-7 a
#
###########################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "--------------------------------------"
diag_out "STIG Finding ID: V-230343"
diag_out "     User names must be logged on"
diag_out "     failed login attempts
diag_out "--------------------------------------"
