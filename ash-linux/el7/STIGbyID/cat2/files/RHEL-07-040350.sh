#!/bin/sh
# Vuln ID:      V-72243
# Finding ID:	RHEL-07-040350
# Version:	SV-86867r3_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	The Red Hat Enterprise Linux operating system must be
#	configured so that the SSH daemon does not allow
#	authentication using rhosts authentication.
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
diag_out "STIG Finding ID: RHEL-07-040350"
diag_out "   Ooperating system must be configured" 
diag_out "   so that the SSH daemon does not allow"
diag_out "   use of rhosts-based authentication."
diag_out "----------------------------------------"
