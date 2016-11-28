#!/bin/sh
# Finding ID:	RHEL-07-040620
# Version:	RHEL-07-040620_rule
# SRG ID:	SRG-OS-000250-GPOS-00093
# Finding Level:	medium
# 
# Rule Summary:
#	The SSH daemon must be configured to only use Message
#	Authentication Codes (MACs) employing FIPS 140-2 approved
#	cryptographic hash algorithms.
#
# CCI-001453 
#    NIST SP 800-53 :: AC-17 (2) 
#    NIST SP 800-53A :: AC-17 (2).1 
#    NIST SP 800-53 Revision 4 :: AC-17 (2) 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-040620"
diag_out "   The SSH daemon must be configured to"
diag_out "   only use Message Authentication"
diag_out "   Codes (MACs) employing FIPS 140-2"
diag_out "   approved cryptographic hash"
diag_out "   algorithms."
diag_out "----------------------------------------"
