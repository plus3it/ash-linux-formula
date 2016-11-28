#!/bin/sh
# Finding ID:	RHEL-07-020140
# Version:	RHEL-07-020140_rule
# SRG ID:	SRG-OS-000363-GPOS-00150
# Finding Level:	medium
# 
# Rule Summary:
#	Designated personnel must be notified if baseline configurations
#	are changed in an unauthorized manner.
#
# CCI-001744 
#    NIST SP 800-53 Revision 4 :: CM-3 (5) 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-020140"
diag_out "   Designated personnel must be"
diag_out "   notified if baseline configurations"
diag_out "   are changed in an unauthorized"
diag_out "   manner."
diag_out "----------------------------------------"
