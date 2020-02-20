#!/bin/sh
# STIG ID:      RHEL-07-030840
# Rule ID:      SV-86815r5_rule
# Vuln ID:      V-72191
# SRG ID:	SRG-OS-000471-GPOS-00216
# Finding Level:	medium
# 
# Rule Summary:
#	System must audit all uses of the kmod command
#
# CCI-000172 
#    NIST SP 800-53 :: AU-12 c 
#    NIST SP 800-53A :: AU-12.1 (iv) 
#    NIST SP 800-53 Revision 4 :: AU-12 c 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-030840"
diag_out "   All uses of the kmod command must be"
diag_out "   audited."
diag_out "----------------------------------------"
