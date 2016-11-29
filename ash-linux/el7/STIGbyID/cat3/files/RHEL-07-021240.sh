#!/bin/bash
#
# Finding ID:	RHEL-07-021240
# Version:	RHEL-07-021240_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	low
# 
# Rule Summary:
#	A separate file system must be used for user home
#	directories (such as /home or an equivalent).
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
diag_out "STIG Finding ID: RHEL-07-021240"
diag_out "   A separate file system must be used"
diag_out "   for user home directories (such as"
diag_out "   /home or an equivalent)."
diag_out "----------------------------------------"
