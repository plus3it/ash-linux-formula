#!/bin/sh
# STIG ID:	RHEL-07-030330
# Rule ID:	SV-86713r4_rule
# Vuln ID:	V-72089
# SRG ID:	SRG-OS-000343-GPOS-00134
# Finding Level:	medium
# 
# Rule Summary:
#	The operating system must immediately notify the System
#	Administrator (SA) and Information System Security Officer
#	ISSO (at a minimum) when allocated audit record storage
#	volume reaches 75% of the repository maximum audit record
#	storage capacity.
#
# CCI-001855 
#    NIST SP 800-53 Revision 4 :: AU-5 (1) 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-030330"
diag_out "   Alert when allocated audit record"
diag_out "   storage volume reaches 75% of the"
diag_out "   repository maximum audit record"
diag_out "   storage capacity."
diag_out "----------------------------------------"
