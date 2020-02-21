#!/bin/sh
# STIG ID:	RHEL-07-040110
# Rule ID:	SV-86845r3_rule
# Vuln ID:	V-72221
# SRG ID:	SRG-OS-000033-GPOS-00014
# Finding Level:	medium
# 
# Rule Summary:
#	A FIPS 140-2 approved cryptographic algorithm must be used for
#	SSH communications.
#
# CCI-000068 
# CCI-000366 
# CCI-000803 
#    NIST SP 800-53 :: AC-17 (2) 
#    NIST SP 800-53A :: AC-17 (2).1 
#    NIST SP 800-53 Revision 4 :: AC-17 (2) 
#    NIST SP 800-53 :: CM-6 b 
#    NIST SP 800-53A :: CM-6.1 (iv) 
#    NIST SP 800-53 Revision 4 :: CM-6 b 
#    NIST SP 800-53 :: IA-7 
#    NIST SP 800-53A :: IA-7.1 
#    NIST SP 800-53 Revision 4 :: IA-7 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-040110"
diag_out "   A FIPS 140-2 approved cryptographic"
diag_out "   algorithm must be used for SSH"
diag_out "   communications."
diag_out "----------------------------------------"
