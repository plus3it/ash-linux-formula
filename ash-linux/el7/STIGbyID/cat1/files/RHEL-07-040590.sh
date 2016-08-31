#!/bin/bash
#
# Finding ID:	RHEL-07-040590
# Version:	RHEL-07-040590_rule
# SRG ID:	SRG-OS-000074-GPOS-00042
# Finding Level:	high
#
# Rule Summary:
#	The SSH daemon must be configured to only use the SSHv2 protocol.
#
# CCI-000197
# CCI-000366
#    NIST SP 800-53 :: IA-5 (1) (c)
#    NIST SP 800-53A :: IA-5 (1).1 (v)
#    NIST SP 800-53 Revision 4 :: IA-5 (1) (c)
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
diag_out "STIG Finding ID: RHEL-07-040590"
diag_out "   The SSH daemon must be configured to"
diag_out "   only use the SSHv2 protocol."
diag_out "----------------------------------------"
