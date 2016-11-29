#!/bin/bash
#
# Finding ID:	RHEL-07-021250
# Version:	RHEL-07-021250_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	low
# 
# Rule Summary:
#	The system must use a separate file system for /var.
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
diag_out "STIG Finding ID: RHEL-07-021250"
diag_out "   The system must use a separate file"
diag_out "   system for /var."
diag_out "----------------------------------------"
