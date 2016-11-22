#!/bin/sh
# Finding ID:	RHEL-07-040680
# Version:	RHEL-07-040680_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	The SSH daemon must perform strict mode checking of home
#	directory configuration files.
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
diag_out "STIG Finding ID: RHEL-07-040680"
diag_out "   The SSH daemon must perform strict"
diag_out "   mode checking of home directory"
diag_out "   configuration files."
diag_out "----------------------------------------"
