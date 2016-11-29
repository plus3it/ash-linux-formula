#!/bin/bash
#
# Finding ID:	RHEL-07-021600
# Version:	RHEL-07-021600_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	low
# 
# Rule Summary:
#	The file integrity tool must be configured to verify
#	Access Control Lists (ACLs).
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
diag_out "STIG Finding ID: RHEL-07-021600"
diag_out "   The file integrity tool must be"
diag_out "   configured to verify Access Control"
diag_out "   Lists (ACLs)."
diag_out "----------------------------------------"
