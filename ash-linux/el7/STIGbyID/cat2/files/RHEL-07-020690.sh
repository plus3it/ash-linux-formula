#!/bin/sh
# Finding ID:	RHEL-07-020690
# Version:	RHEL-07-020690_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	All files and directories contained in local interactive user
#	home directories must be group-owned by a group of which the
#	home directory owner is a member.
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
diag_out "STIG Finding ID: RHEL-07-020690"
diag_out "   All files and directories contained"
diag_out "   in local interactive user home"
diag_out "   directories must be group-owned by a"
diag_out "   group of which the home directory"
diag_out "   owner is a member."
diag_out "----------------------------------------"
