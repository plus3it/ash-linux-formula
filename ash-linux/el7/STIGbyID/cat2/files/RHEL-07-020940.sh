#!/bin/sh
# Finding ID:	RHEL-07-020940
# Version:	RHEL-07-020940_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	All system device files must be correctly labeled to prevent
#	unauthorized modification.
#
# CCI-000318 
# CCI-001812 
# CCI-001813 
# CCI-001814 
# CCI-000368 
#    NIST SP 800-53 :: CM-3 e 
#    NIST SP 800-53A :: CM-3.1 (v) 
#    NIST SP 800-53 Revision 4 :: CM-3 f 
#    NIST SP 800-53 Revision 4 :: CM-11 (2) 
#    NIST SP 800-53 Revision 4 :: CM-5 (1) 
#    NIST SP 800-53 Revision 4 :: CM-5 (1) 
#    NIST SP 800-53 :: CM-6 c 
#    NIST SP 800-53A :: CM-6.1 (v) 
#    NIST SP 800-53 Revision 4 :: CM-6 c 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-020940"
diag_out "   All system device files must be"
diag_out "   correctly labeled to prevent"
diag_out "   unauthorized modification."
diag_out "----------------------------------------"
