#!/bin/sh
# Finding ID:	RHEL-07-040560
# Version:	RHEL-07-040560_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	An X Windows display manager must not be installed unless approved.
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
diag_out "STIG Finding ID: RHEL-07-040560"
diag_out "   An X Windows display manager must"
diag_out "   not be installed unless approved."
diag_out "----------------------------------------"
