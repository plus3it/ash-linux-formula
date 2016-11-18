#!/bin/sh
# Finding ID:	RHEL-07-040290
# Version:	RHEL-07-040290_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	The operating system must enable an application firewall,
#	if available.
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
diag_out "STIG Finding ID: RHEL-07-040290"
diag_out "   The operating system must enable an"
diag_out "   application firewall, if available."
diag_out "----------------------------------------"
