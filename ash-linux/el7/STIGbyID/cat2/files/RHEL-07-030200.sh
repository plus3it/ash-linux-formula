#!/bin/bash
# STIG ID:	RHEL-07-030200
# Rule ID:	SV-95727r1_rule
# Vuln ID:	V-81015
# SRG ID:	SRG-OS-000342-GPOS-00133
#               SRG-OS-000479-GPOS-00224
# Finding Level:	medium
# 
# Rule Summary:
#       The operating system must be configured to use the au-remote plugin.
#
# CCI-001851 
#    NIST SP 800-53 Revision 4 :: AU-4 (1) 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-030200"
diag_out "   The operating system must be"
diag_out "   configured to use the au-remote"
diag_out "   plugin."
diag_out "----------------------------------------"

