#!/bin/sh
# STIG ID:	RHEL-07-020100
# Rule ID:	SV-86607r4_rule
# Vuln ID:	V-71983
# SRG ID:	SRG-OS-000114-GPOS-00059
# Finding Level:	medium
# 
# Rule Summary:
#	USB mass storage must be disabled.
#
# CCI-000366 
# CCI-000778 
# CCI-001958 
#    NIST SP 800-53 :: CM-6 b 
#    NIST SP 800-53A :: CM-6.1 (iv) 
#    NIST SP 800-53 Revision 4 :: CM-6 b 
#    NIST SP 800-53 :: IA-3 
#    NIST SP 800-53A :: IA-3.1 (ii) 
#    NIST SP 800-53 Revision 4 :: IA-3 
#    NIST SP 800-53 Revision 4 :: IA-3 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-020100"
diag_out "   USB mass storage must be disabled."
diag_out "----------------------------------------"
