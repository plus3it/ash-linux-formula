#!/bin/sh
# Finding ID:	RHEL-07-040520
# Version:	RHEL-07-040520_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	If the Trivial File Transfer Protocol (TFTP) server is required,
#	the TFTP daemon must be configured to operate in secure mode.
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
diag_out "STIG Finding ID: RHEL-07-040520"
diag_out "   If the Trivial File Transfer"
diag_out "   Protocol (TFTP) server is required,"
diag_out "   the TFTP daemon must be configured"
diag_out "   to operate in secure mode."
diag_out "----------------------------------------"
