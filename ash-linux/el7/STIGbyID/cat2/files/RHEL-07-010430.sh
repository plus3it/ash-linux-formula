#!/bin/sh
# STIG ID:	RHEL-07-010430
# Rule ID:	SV-86575r2_rule
# Vuln ID:	V-71951
# SRG ID:	SRG-OS-000480-GPOS-00226
# Finding Level:	medium
# 
# Rule Summary:
#	The delay between logon prompts following a failed console
#	logon attempt must be at least four seconds.
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
diag_out "STIG Finding ID: RHEL-07-010430"
diag_out "   The delay between logon prompts"
diag_out "   following a failed console logon"
diag_out "   attempt must be at least four"
diag_out "   seconds."
diag_out "----------------------------------------"
