#!/bin/sh
# Finding ID:	RHEL-07-020630
# Version:	RHEL-07-020630_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	All local interactive user accounts, upon creation, must be
#	assigned a home directory.
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
diag_out "STIG Finding ID: RHEL-07-020630"
diag_out "   All local interactive user accounts,"
diag_out "   upon creation, must be assigned a"
diag_out "   home directory."
diag_out "----------------------------------------"
