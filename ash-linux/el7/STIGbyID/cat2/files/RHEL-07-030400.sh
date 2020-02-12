#!/bin/sh
# Finding ID:	RHEL-07-030400
# Version:	RHEL-07-030400_rule
# SRG ID:	SRG-OS-000064-GPOS-00033
# Finding Level:	medium
# 
# Rule Summary:
#	All uses of the fchownat command must be audited.
#
# CCI-000172 
# CCI-000126 
#    NIST SP 800-53 :: AU-12 c 
#    NIST SP 800-53A :: AU-12.1 (iv) 
#    NIST SP 800-53 Revision 4 :: AU-12 c 
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
diag_out "STIG Finding ID: RHEL-07-030400"
diag_out "   All uses of the fchownat command"
diag_out "   must be audited."
diag_out "----------------------------------------"
