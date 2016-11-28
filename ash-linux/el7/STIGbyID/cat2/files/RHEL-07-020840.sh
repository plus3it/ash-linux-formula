#!/bin/sh
# Finding ID:	RHEL-07-020840
# Version:	RHEL-07-020840_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	All local initialization files for interactive users must be
#	owned by the home directory user or root.
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
diag_out "STIG Finding ID: RHEL-07-020840"
diag_out "   All local initialization files for"
diag_out "   interactive users must be owned by"
diag_out "   the home directory user or root."
diag_out "----------------------------------------"
