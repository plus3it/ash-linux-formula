#!/bin/sh
# Finding ID:	RHEL-07-020860
# Version:	RHEL-07-020860_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	All local initialization files must have mode 0740 or less permissive.
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
diag_out "STIG Finding ID: RHEL-07-020860"
diag_out "   All local initialization files must"
diag_out "   have mode 0740 or less permissive."
diag_out "----------------------------------------"
