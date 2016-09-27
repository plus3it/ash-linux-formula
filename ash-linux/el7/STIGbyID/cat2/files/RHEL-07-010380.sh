#!/bin/sh
# Finding ID:	RHEL-07-010380
# Version:	RHEL-07-010380_rule
# SRG ID:	SRG-OS-000373-GPOS-00156
# Finding Level:	medium
# 
# Rule Summary:
#	Users must provide a password for privilege escalation.
#
# CCI-002038 
#    NIST SP 800-53 Revision 4 :: IA-11 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-010380"
diag_out "   Users must provide a password for"
diag_out "   privilege escalation."
diag_out "----------------------------------------"
