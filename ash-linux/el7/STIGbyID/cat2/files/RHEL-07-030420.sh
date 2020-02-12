#!/bin/sh
# Finding ID:	RHEL-07-030420
# Version:	RHEL-07-030420_rule
# SRG ID:	SRG-OS-000458-GPOS-00203
# Finding Level:	medium
# 
# Rule Summary:
#	All uses of the fchmod command must be audited.
#
# CCI-000172 
#    NIST SP 800-53 :: AU-12 c 
#    NIST SP 800-53A :: AU-12.1 (iv) 
#    NIST SP 800-53 Revision 4 :: AU-12 c 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-030420"
diag_out "   All uses of the fchmod command must"
diag_out "   be audited."
diag_out "----------------------------------------"
