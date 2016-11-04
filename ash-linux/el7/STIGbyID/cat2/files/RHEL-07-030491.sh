#!/bin/sh
# Finding ID:	RHEL-07-030491
# Version:	RHEL-07-030491_rule
# SRG ID:	SRG-OS-000392-GPOS-00172
# Finding Level:	medium
# 
# Rule Summary:
#	The operating system must generate audit records for all
#	unsuccessful account access events.
#
# CCI-000172 
# CCI-002884 
# CCI-000126 
#    NIST SP 800-53 :: AU-12 c 
#    NIST SP 800-53A :: AU-12.1 (iv) 
#    NIST SP 800-53 Revision 4 :: AU-12 c 
#    NIST SP 800-53 Revision 4 :: MA-4 (1) (a) 
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
diag_out "STIG Finding ID: RHEL-07-030491"
diag_out "   The operating system must generate"
diag_out "   audit records for all unsuccessful"
diag_out "   account access events."
diag_out "----------------------------------------"
