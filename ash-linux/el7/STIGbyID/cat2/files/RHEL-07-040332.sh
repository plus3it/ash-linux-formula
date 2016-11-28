#!/bin/sh
# Finding ID:	RHEL-07-040332
# Version:	RHEL-07-040332_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	The SSH daemon must not allow authentication using known
#	hosts authentication.
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
diag_out "STIG Finding ID: RHEL-07-040332"
diag_out "   The SSH daemon must not allow"
diag_out "   authentication using known hosts"
diag_out "   authentication."
diag_out "----------------------------------------"
