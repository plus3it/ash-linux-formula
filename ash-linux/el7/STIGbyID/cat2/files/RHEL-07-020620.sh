#!/bin/sh
# Finding ID:	RHEL-07-020620
# Version:	RHEL-07-020620_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	All local interactive users must have a home directory assigned
#	in the /etc/passwd file.
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
diag_out "STIG Finding ID: RHEL-07-020620"
diag_out "   All local interactive users must"
diag_out "   have a home directory assigned in"
diag_out "   the /etc/passwd file."
diag_out "----------------------------------------"
