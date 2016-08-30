#!/bin/bash
#
# Finding ID:	RHEL-07-040540
# Version:	RHEL-07-040540_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	high
# 
# Rule Summary:
#	Remote X connections for interactive users must be encrypted.
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
diag_out "STIG Finding ID: RHEL-07-040540"
diag_out "   Remote X connections for interactive"
diag_out "   users must be encrypted."
diag_out "----------------------------------------"

