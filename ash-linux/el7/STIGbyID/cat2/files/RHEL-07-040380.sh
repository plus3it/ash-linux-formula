#!/bin/sh
# Finding ID:	RHEL-07-040380
# Version:	RHEL-07-040380_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	The system must not respond to Internet Protocol version 4
#	(IPv4) Internet Control Message Protocol (ICMP) echoes sent
#	to a broadcast address.
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
diag_out "STIG Finding ID: RHEL-07-040380"
diag_out "   The system must not respond to"
diag_out "   Internet Protocol version 4 (IPv4)"
diag_out "   Internet Control Message Protocol"
diag_out "   (ICMP) echoes sent to a broadcast"
diag_out "   address."
diag_out "----------------------------------------"
