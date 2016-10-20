#!/bin/sh
# Finding ID:	RHEL-07-020700
# Version:	RHEL-07-020700_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	All files and directories contained in local interactive user
#	home directories must have mode 0750 or less permissive.
#
# CCI-000366 
#    NIST SP 800-53 :: CM-6 b 
#    NIST SP 800-53A :: CM-6.1 (iv) 
#    NIST SP 800-53 Revision 4 :: CM-6 b 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-020700"
diag_out "   All files and directories contained"
diag_out "   in local interactive user home"
diag_out "   directories must have mode 0750 or"
diag_out "   less permissive."
diag_out "----------------------------------------"
