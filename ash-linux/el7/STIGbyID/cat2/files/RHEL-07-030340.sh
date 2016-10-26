#!/bin/sh
# Finding ID:	RHEL-07-030340
# Version:	RHEL-07-030340_rule
# SRG ID:	SRG-OS-000342-GPOS-00133
# Finding Level:	medium
# 
# Rule Summary:
#	The audit system must take appropriate action when the audit
#	storage volume is full.
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
diag_out "STIG Finding ID: RHEL-07-030340"
diag_out "   The audit system must take"
diag_out "   appropriate action when the audit"
diag_out "   storage volume is full."
diag_out "----------------------------------------"
