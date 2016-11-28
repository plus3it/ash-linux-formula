#!/bin/sh
# Finding ID:	RHEL-07-040730
# Version:	RHEL-07-040730_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	The system must not be performing packet forwarding unless
#	the system is a router.
#
# CCI-000366 
#    NIST SP 800-53 :: CM-6 b 
#    NIST SP 800-53A :: CM-6.1 (iv) 
#    NIST SP 800-53 Revision 4 :: CM-6 b 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-040730"
diag_out "   The system must not be performing"
diag_out "   packet forwarding unless the system"
diag_out "   is a router."
diag_out "----------------------------------------"
