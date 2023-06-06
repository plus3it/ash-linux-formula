#!/bin/sh
# Ref Doc:        STIG - RHEL 7 v3r11
# Finding ID:     V-204463
# STIG ID:        RHEL-07-020320
# Version:        RHEL-07-020320_rule
# SRG ID:         SRG-OS-000480-GPOS-00227
# Finding Level:  medium
# 
# Rule Summary:
#	All files and directories must have a valid owner.
#
# CCI-002165 
#    NIST SP 800-53 Revision 4 :: AC-3 (4) 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-020320"
diag_out "   All files and directories must have"
diag_out "   a valid owner."
diag_out "----------------------------------------"
