#!/bin/bash
#
# Vuln ID:	V-81005
# STIG ID:	RHEL-07-010482
# Rule ID:      SV-95717r1_rule
# SRG ID(s):    SRG-OS-000080-GPOS-00048
# Finding Level:        high
#
# Rule Summary:
#       Red Hat Enterprise Linux operating systems version 7.2
#       or newer with a Basic Input/Output System (BIOS) must
#       require authentication upon booting into single-user
#       and maintenance modes.
#
# CCI-000213
#    NIST SP 800-53 :: AC-3
#    NIST SP 800-53A :: AC-3.1
#    NIST SP 800-53 Revision 4 :: AC-3
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-021350"
diag_out "   Configure the GRUB2 boot-loader to"
diag_out "   a password to boot into single user"
diag_out "   or other alternate modes"
diag_out "----------------------------------------"
