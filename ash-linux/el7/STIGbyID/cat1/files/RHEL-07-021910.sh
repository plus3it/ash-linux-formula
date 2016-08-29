#!/bin/bash
#
# Finding ID:	RHEL-07-021910
# Version:	RHEL-07-021910_rule
# SRG ID:	SRG-OS-000095-GPOS-00049
# Finding Level:	high
# 
# Rule Summary:
#	The telnet-server package must not be installed.
#
# CCI-000381 
#    NIST SP 800-53 :: CM-7 
#    NIST SP 800-53A :: CM-7.1 (ii) 
#    NIST SP 800-53 Revision 4 :: CM-7 a 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-021910"
diag_out "   The telnet-server package must not"
diag_out "   be installed."
diag_out "----------------------------------------"

