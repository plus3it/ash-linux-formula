#!/bin/sh
# Finding ID:	RHEL-07-020370
# Version:	RHEL-07-020370_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	All files and directories must have a valid group owner.
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
diag_out "STIG Finding ID: RHEL-07-020370"
diag_out "   All files and directories must have"
diag_out "   a valid group owner."
diag_out "----------------------------------------"
