#!/bin/sh
#
# Ref Doc:    STIG - RHEL 8 v1r7
# Finding ID: V-230511
# Rule ID:    SV-230511r627750_rule
# STIG ID:    RHEL-08-040123
# SRG ID:     SRG-OS-000368-GPOS-00154
#
# Finding Level: medium
#
# Rule Summary:
#       The operating system must mount /tmp with the nodev
#       option
#
# References:
#   CCI:
#     - CCI-001764
#
# NIST SP 800-53 Revision 4 :: CM-7 (2)
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "--------------------------------------"
diag_out "STIG Finding ID: mount_options_tmp"
diag_out "   Set nodev, noexec and nosuid mount-"
diag_out "   options on /tmp to prevent abuses."
diag_out "--------------------------------------"
