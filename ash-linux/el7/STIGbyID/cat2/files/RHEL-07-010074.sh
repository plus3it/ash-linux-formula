#!/bin/sh
# Finding ID:	RHEL-07-010074
# Version:	RHEL-07-010074_rule
# SRG ID:	SRG-OS-000029-GPOS-00010
# Finding Level:	medium
# 
# Rule Summary:
#	The operating system must initiate a session lock for
#	graphical user interfaces when the screensaver is activated.
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
diag_out "STIG Finding ID: RHEL-07-010074"
diag_out "----------------------------------------"