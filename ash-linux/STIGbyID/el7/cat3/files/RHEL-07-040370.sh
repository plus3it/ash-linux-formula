#!/bin/sh
#
# STIG URL:
# Finding ID:	RHEL-07-040370
# Version:	RHEL-07-040370_rule
# SRG ID:	
# Finding Level:	low
#
# Rule Summary:
#     The system must not process IPv4 Internet Control Message 
#     Protocol (ICMP) timestamp requests.
#
# CCI-000366
#    NIST SP 800-53 :: CM-6 b
#    NIST SP 800-53A :: CM-6.1 (iv)
#    NIST SP 800-53 Revision 4 :: CM-6 b
#
#################################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: RHEL-07-040370"
diag_out "   The system must not process"
diag_out "   IPv4 Internet Control Message"
diag_out "   Protocol (ICMP) timestamp"
diag_out "   requests."
diag_out "----------------------------------"
