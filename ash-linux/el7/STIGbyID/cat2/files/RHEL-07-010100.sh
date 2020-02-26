#!/bin/sh
# Finding ID:	RHEL-07-010100
# Version:	RHEL-07-010100_rule
# SRG ID:	SRG-OS-000029-GPOS-00010
# Finding Level:	medium
# 
# Rule Summary:
#	The operating system must initiate a session lock for the
#	screensaver after a period of inactivity for graphical user
#	interfaces.
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
diag_out "STIG Finding ID: RHEL-07-010100"
diag_out "  The operating system must initiate a"
diag_out "  session lock for the screensaver"
diag_out "  after a period of inactivity for"
diag_out "  graphical user interfaces."
diag_out "----------------------------------------"
