#!/bin/sh
# Finding ID:	RHEL-07-030310
# Version:	RHEL-07-030310_rule
# SRG ID:	SRG-OS-000327-GPOS-00127
# Finding Level:	medium
# 
# Rule Summary:
#	All privileged function executions must be audited.
#
# CCI-002234 
#    NIST SP 800-53 Revision 4 :: AC-6 (9) 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-030310"
diag_out "   All privileged function executions"
diag_out "   must be audited."
diag_out "----------------------------------------"
