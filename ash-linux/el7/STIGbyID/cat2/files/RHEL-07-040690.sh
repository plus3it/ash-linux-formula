#!/bin/sh
# Finding ID:	RHEL-07-040690
# Version:	RHEL-07-040690_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	The SSH daemon must use privilege separation.
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
diag_out "STIG Finding ID: RHEL-07-040690"
diag_out "   The SSH daemon must use privilege"
diag_out "   separation."
diag_out "----------------------------------------"
