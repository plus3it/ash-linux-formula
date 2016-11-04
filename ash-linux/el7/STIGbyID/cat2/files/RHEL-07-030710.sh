#!/bin/sh
# Finding ID:	RHEL-07-030710
# Version:	RHEL-07-030710_rule
# SRG ID:	SRG-OS-000004-GPOS-00004
# Finding Level:	medium
# 
# Rule Summary:
#	The operating system must generate audit records for all
#	account creations, modifications, disabling, and termination
#	events.
#
# CCI-000018 
# CCI-000172 
# CCI-001403 
# CCI-002130 
#    NIST SP 800-53 :: AC-2 (4) 
#    NIST SP 800-53A :: AC-2 (4).1 (i&ii) 
#    NIST SP 800-53 Revision 4 :: AC-2 (4) 
#    NIST SP 800-53 :: AU-12 c 
#    NIST SP 800-53A :: AU-12.1 (iv) 
#    NIST SP 800-53 Revision 4 :: AU-12 c 
#    NIST SP 800-53 :: AC-2 (4) 
#    NIST SP 800-53A :: AC-2 (4).1 (i&ii) 
#    NIST SP 800-53 Revision 4 :: AC-2 (4) 
#    NIST SP 800-53 Revision 4 :: AC-2 (4) 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-030710"
diag_out "   The operating system must generate"
diag_out "   audit records for all account"
diag_out "   creations, modifications, disabling,"
diag_out "   and termination events."
diag_out "----------------------------------------"
