#!/bin/bash
#
# Finding ID:	RHEL-07-040320
# Version:	RHEL-07-040320_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	low
# 
# Rule Summary:
#	For systems using DNS resolution, at least two name
#	servers must be configured.
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
diag_out "STIG Finding ID: RHEL-07-040320"
diag_out "   For systems using DNS resolution, at"
diag_out "   least two name servers must be"
diag_out "   configured."
diag_out "----------------------------------------"
