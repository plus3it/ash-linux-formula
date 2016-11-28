#!/bin/sh
# Finding ID:	RHEL-07-040420
# Version:	RHEL-07-040420_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	The system must not allow interfaces to perform Internet
#	Protocol version 4 (IPv4) Internet Control Message Protocol
#	(ICMP) redirects by default.
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
diag_out "STIG Finding ID: RHEL-07-040420"
diag_out "   The system must not allow interfaces"
diag_out "   to perform Internet Protocol version"
diag_out "   4 (IPv4) Internet Control Message"
diag_out "   Protocol (ICMP) redirects by default."
diag_out "----------------------------------------"
