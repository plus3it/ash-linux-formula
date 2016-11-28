#!/bin/sh
# Finding ID:	RHEL-07-040700
# Version:	RHEL-07-040700_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	The SSH daemon must not allow compression or must only allow
#	compression after successful authentication.
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
diag_out "STIG Finding ID: RHEL-07-040700"
diag_out "   The SSH daemon must not allow"
diag_out "   compression or must only allow"
diag_out "   compression after successful"
diag_out "   authentication."
diag_out "----------------------------------------"
