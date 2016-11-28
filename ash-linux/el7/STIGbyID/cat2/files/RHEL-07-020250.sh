#!/bin/sh
# Finding ID:	RHEL-07-020250
# Version:	RHEL-07-020250_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	System security patches and updates must be installed and up to date.
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
diag_out "STIG Finding ID: RHEL-07-020250"
diag_out "   System security patches and updates"
diag_out "   must be installed and up to date."
diag_out "----------------------------------------"
