#!/bin/sh
# Finding ID:	RHEL-07-040250
# Version:	RHEL-07-040250_rule
# SRG ID:	SRG-OS-000420-GPOS-00186
# Finding Level:	medium
# 
# Rule Summary:
#	The operating system must protect against or limit the effects
#	of Denial of Service (DoS) attacks by validating the operating
#	system is implementing rate-limiting measures on impacted
#	network interfaces.
#
# CCI-002385 
#    NIST SP 800-53 Revision 4 :: SC-5 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-040250"
diag_out "   The operating system must protect"
diag_out "   against or limit the effects of"
diag_out "   Denial of Service (DoS) attacks by"
diag_out "   validating the operating system is"
diag_out "   implementing rate-limiting measures"
diag_out "   on impacted network interfaces."
diag_out "----------------------------------------"
