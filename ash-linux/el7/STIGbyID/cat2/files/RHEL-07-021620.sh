#!/bin/sh
# Finding ID:	RHEL-07-021620
# Version:	RHEL-07-021620_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	The file integrity tool must use FIPS 140-2 approved
#	cryptographic hashes for validating file contents and
#	directories.
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
diag_out "STIG Finding ID: RHEL-07-021620"
diag_out "  The file integrity tool must use"
diag_out "  FIPS 140-2 approved cryptographic"
diag_out "  hashes for validating file contents"
diag_out "  and directories."
diag_out "----------------------------------------"
