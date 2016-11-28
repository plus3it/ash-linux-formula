#!/bin/sh
# Finding ID:	RHEL-07-040421
# Version:	RHEL-07-040421_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	The system must not send Internet Protocol version 4 (IPv4)
#	Internet Control Message Protocol (ICMP) redirects.
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
diag_out "STIG Finding ID: RHEL-07-040421"
diag_out "   The system must not send Internet"
diag_out "   Protocol version 4 (IPv4) Internet"
diag_out "   Control Message Protocol (ICMP)"
diag_out "   redirects."
diag_out "----------------------------------------"
