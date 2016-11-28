#!/bin/sh
# Finding ID:	RHEL-07-020360
# Version:	RHEL-07-020360_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
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
diag_out "STIG Finding ID: RHEL-07-020360"
diag_out "   All files and directories must have"
diag_out "   a valid owner."
diag_out "----------------------------------------"
