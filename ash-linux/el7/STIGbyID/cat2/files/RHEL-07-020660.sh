#!/bin/sh
# Finding ID:	RHEL-07-020660
# Version:	RHEL-07-020660_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	All local interactive user home directories must be owned by
#	their respective users.
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
diag_out "STIG Finding ID: RHEL-07-020660"
diag_out "   All local interactive user home"
diag_out "   directories must be owned by their"
diag_out "   respective users."
diag_out "----------------------------------------"
