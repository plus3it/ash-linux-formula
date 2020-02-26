#!/bin/sh
# STIG ID:	RHEL-07-030360
# Rule ID:	SV-86719r7_rule
V# uln ID:	V-72095
# SRG ID:	SRG-OS-000466-GPOS-00210
# Finding Level:	medium
# 
# Rule Summary:
#	Audit all executions of privileged functions
#
# CCI-000172 
# CCI-002884 
#    NIST SP 800-53 :: AU-12 c 
#    NIST SP 800-53A :: AU-12.1 (iv) 
#    NIST SP 800-53 Revision 4 :: AU-12 c 
#    NIST SP 800-53 Revision 4 :: MA-4 (1) (a) 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-030360"
diag_out "   Audit all executions of privileged" 
diag_out "   functions."
diag_out "----------------------------------------"
