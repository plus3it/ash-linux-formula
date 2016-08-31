#!/bin/bash
#
# Finding ID:	RHEL-07-010440
# Version:	RHEL-07-010440_rule
# SRG ID:	SRG-OS-000480-GPOS-00229
# Finding Level:	high
#
# Rule Summary:
#	The operating system must not allow empty passwords for SSH
#	logon to the system.
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
diag_out "STIG Finding ID: RHEL-07-010440"
diag_out "   The operating system must not allow"
diag_out "   empty passwords for SSH logon to the"
diag_out "   system."
diag_out "----------------------------------------"

