#!/bin/sh
# Finding ID:	RHEL-07-020670
# Version:	RHEL-07-020670_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	All local interactive user home directories must be group-
#	owned by the home directory owners primary group.
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
diag_out "STIG Finding ID: RHEL-07-020670"
diag_out "   All local interactive user home"
diag_out "   directories must be group-owned by"
diag_out "   the home directory owners primary"
diag_out "   group."
diag_out "----------------------------------------"
