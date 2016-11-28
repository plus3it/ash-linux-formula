#!/bin/sh
# Finding ID:	RHEL-07-020230
# Version:	RHEL-07-020230_rule
# SRG ID:	SRG-OS-000480-GPOS-00228
# Finding Level:	medium
# 
# Rule Summary:
#	The operating system must define default permissions for all
#	authenticated users in such a way that the user can only read
#	and modify their own files.
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
diag_out "STIG Finding ID: RHEL-07-020230"
diag_out "   The operating system must define"
diag_out "   default permissions for all"
diag_out "   authenticated users in such a way"
diag_out "   that the user can only read and"
diag_out "   modify their own files."
diag_out "----------------------------------------"
