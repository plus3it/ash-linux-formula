#!/bin/sh
# Finding ID:	RHEL-07-040020
# Version:	RHEL-07-040020_rule
# SRG ID:	SRG-OS-000032-GPOS-00013
# Finding Level:	medium
# 
# Rule Summary:
#	The system must log informational authentication data.
#
# CCI-000067 
# CCI-000126 
#    NIST SP 800-53 :: AC-17 (1) 
#    NIST SP 800-53A :: AC-17 (1).1 
#    NIST SP 800-53 Revision 4 :: AC-17 (1) 
#    NIST SP 800-53 :: AU-2 d 
#    NIST SP 800-53A :: AU-2.1 (v) 
#    NIST SP 800-53 Revision 4 :: AU-2 d 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-040020"
diag_out "   The system must log informational"
diag_out "   authentication data."
diag_out "----------------------------------------"
