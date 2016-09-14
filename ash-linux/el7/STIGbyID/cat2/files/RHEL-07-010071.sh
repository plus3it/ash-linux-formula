#!/bin/sh
# Finding ID:	RHEL-07-010071
# Version:	RHEL-07-010071_rule
# SRG ID:	SRG-OS-000029-GPOS-00010
# Finding Level:	medium
# 
# Rule Summary:
#	The operating system must initiate a session lock after a
#	15-minute period of inactivity for all connection types.
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
diag_out "STIG Finding ID: RHEL-07-010071"
diag_out "   The operating system must initiate a"
diag_out "   session lock after a 15-minute"
diag_out "   period of inactivity for all"
diag_out "   connection types."
diag_out "----------------------------------------"
