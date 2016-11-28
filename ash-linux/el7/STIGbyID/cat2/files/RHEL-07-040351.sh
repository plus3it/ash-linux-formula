#!/bin/sh
# Finding ID:	RHEL-07-040351
# Version:	RHEL-07-040351_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	The system must not forward Internet Protocol version 4 (IPv4)
#	source-routed packets by default.
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
diag_out "STIG Finding ID: RHEL-07-040351"
diag_out "   The system must not forward Internet"
diag_out "   Protocol version 4 (IPv4)"
diag_out "   source-routed packets by default."
diag_out "----------------------------------------"
