#!/bin/sh
# Finding ID:	RHEL-07-040190
# Version:	RHEL-07-040190_rule
# SRG ID:	SRG-OS-000163-GPOS-00072
# Finding Level:	medium
# 
# Rule Summary:
#	All network connections associated with SSH traffic must
#	terminate at the end of the session or after 10 minutes of
#	inactivity, except to fulfill documented and validated mission
#	requirements.
#
# CCI-001133 
# CCI-002361 
#    NIST SP 800-53 :: SC-10 
#    NIST SP 800-53A :: SC-10.1 (ii) 
#    NIST SP 800-53 Revision 4 :: SC-10 
#    NIST SP 800-53 Revision 4 :: AC-12 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-040190"
diag_out "   All network connections associated"
diag_out "   with SSH traffic must terminate at"
diag_out "   the end of the session or after 10"
diag_out "   minutes of inactivity, except to"
diag_out "   fulfill documented and validated"
diag_out "   mission requirements."
diag_out "----------------------------------------"
