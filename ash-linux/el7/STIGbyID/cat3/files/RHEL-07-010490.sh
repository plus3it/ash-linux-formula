#!/bin/bash
#
# Finding ID:	RHEL-07-010490
# Version:	RHEL-07-010490_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	low
# 
# Rule Summary:
#	Unnecessary default system accounts must be removed.
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
diag_out "STIG Finding ID: RHEL-07-010490"
diag_out "   Unnecessary default system accounts"
diag_out "   must be removed."
diag_out "----------------------------------------"
