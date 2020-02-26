#!/bin/sh
# STIG ID:	RHEL-07-030350
# Rule ID:	SV-86717r3_rule
# Vuln ID:	V-72093
# SRG ID:	SRG-OS-000343-GPOS-00134
# Finding Level:	medium
# 
# Rule Summary:
#	The operating system must immediately notify the System
#	Administrator (SA) and Information System Security Officer
#	(ISSO) (at a minimum) when the threshold for the repository
#	maximum audit record storage capacity is reached.
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
diag_out "STIG Finding ID: RHEL-07-030350"
diag_out "   The operating system must"
diag_out "   immediately notify the SA and ISSO"
diag_out "   (at a minimum) when the threshold"
diag_out "   for the repository maximum audit"
diag_out "   record storage capacity is reached."
diag_out "----------------------------------------"
