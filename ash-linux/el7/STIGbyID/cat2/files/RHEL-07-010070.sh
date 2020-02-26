#!/bin/sh
# STIG ID:	RHEL-07-010070
# Rule ID:	SV-86517r5_rule
# Vuln ID:	V-71893
# SRG ID:	SRG-OS-000029-GPOS-00010
# Finding Level:	medium
# 
# Rule Summary:
#	The operating system must initiate a screensaver after a
#	15-minute period of inactivity for graphical user interfaces.
#
# CCI-000057 
#    NIST SP 800-53 :: AC-11 a 
#    NIST SP 800-53A :: AC-11.1 (ii) 
#    NIST SP 800-53 Revision 4 :: AC-11 a 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-010070"
diag_out "   The operating system must initiate a"
diag_out "   screensaver after a 15-minute period"
diag_out "   of inactivity for graphical user"
diag_out "   interfaces."
diag_out "----------------------------------------"
