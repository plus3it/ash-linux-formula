#!/bin/sh
# Finding ID:	RHEL-07-030523
# Version:	RHEL-07-030523_rule
# SRG ID:	SRG-OS-000037-GPOS-00015
# Finding Level:	medium
# 
# Rule Summary:
#	The operating system must generate audit records containing the
#	full-text recording of modifications to sudo configuration files.
#
# CCI-000130 
# CCI-000135 
# CCI-000172 
# CCI-002884 
#    NIST SP 800-53 :: AU-3 
#    NIST SP 800-53A :: AU-3.1 
#    NIST SP 800-53 Revision 4 :: AU-3 
#    NIST SP 800-53 :: AU-3 (1) 
#    NIST SP 800-53A :: AU-3 (1).1 (ii) 
#    NIST SP 800-53 Revision 4 :: AU-3 (1) 
#    NIST SP 800-53 :: AU-12 c 
#    NIST SP 800-53A :: AU-12.1 (iv) 
#    NIST SP 800-53 Revision 4 :: AU-12 c 
#    NIST SP 800-53 Revision 4 :: MA-4 (1) (a) 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-030523"
diag_out "   The operating system must generate"
diag_out "   audit records containing the"
diag_out "   full-text recording of modifications"
diag_out "   to sudo configuration files."
diag_out "----------------------------------------"
