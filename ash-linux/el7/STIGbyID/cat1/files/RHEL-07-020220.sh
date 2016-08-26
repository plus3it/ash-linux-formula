#!/bin/bash
#
# Finding ID:	RHEL-07-020220
# Version:	RHEL-07-020220_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	high
# 
# Rule Summary:
#	The x86 Ctrl-Alt-Delete key sequence must be disabled.
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
diag_out "STIG Finding ID: RHEL-07-020220"
diag_out "   The x86 Ctrl-Alt-Delete key sequence"
diag_out "   must be disabled."
diag_out "----------------------------------------"
