#!/bin/sh
# Finding ID:	RHEL-07-040191
# Version:	RHEL-07-040191_rule
# SRG ID:	SRG-OS-000163-GPOS-00072
# Finding Level:	medium
# 
# Rule Summary:
#	All network connections associated with SSH traffic must
#	terminate after a period of inactivity.
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
diag_out "STIG Finding ID: RHEL-07-040191"
diag_out "   All network connections associated"
diag_out "   with SSH traffic must terminate"
diag_out "   after a period of inactivity."
diag_out "----------------------------------------"
