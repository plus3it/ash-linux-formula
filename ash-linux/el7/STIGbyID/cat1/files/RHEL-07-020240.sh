#!/bin/bash
#
# Finding ID:	RHEL-07-020240
# Version:	RHEL-07-020240_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	high
# 
# Rule Summary:
#	The operating system must be a supported release.
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
diag_out "STIG Finding ID: RHEL-07-020240"
diag_out "   The operating system must be a"
diag_out "   supported release."
diag_out "----------------------------------------"

