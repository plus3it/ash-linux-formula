#!/bin/sh
# Finding ID:	RHEL-07-021230
# Version:	RHEL-07-021230_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	Kernel core dumps must be disabled unless needed.
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
diag_out "STIG Finding ID: RHEL-07-021230"
diag_out "   Kernel core dumps must be disabled"
diag_out "   unless needed."
diag_out "----------------------------------------"
