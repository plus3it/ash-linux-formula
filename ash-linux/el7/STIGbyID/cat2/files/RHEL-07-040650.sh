#!/bin/sh
# Finding ID:	RHEL-07-040650
# Version:	RHEL-07-040650_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	The SSH private host key files must have mode 0600 or less permissive.
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
diag_out "STIG Finding ID: RHEL-07-040650"
diag_out "   The SSH private host key files must"
diag_out "   have mode 0600 or less permissive."
diag_out "----------------------------------------"
