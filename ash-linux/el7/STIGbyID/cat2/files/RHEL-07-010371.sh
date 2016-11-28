#!/bin/sh
# Finding ID:	RHEL-07-010371
# Version:	RHEL-07-010371_rule
# SRG ID:	SRG-OS-000329-GPOS-00128
# Finding Level:	medium
# 
# Rule Summary:
#	If three unsuccessful logon attempts within 15 minutes occur
#	the associated account must be locked.
#
# CCI-002238 
#    NIST SP 800-53 Revision 4 :: AC-7 b 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-010371"
diag_out "   If three unsuccessful logon attempts"
diag_out "   within 15 minutes occur the"
diag_out "   associated account must be locked."
diag_out "----------------------------------------"
