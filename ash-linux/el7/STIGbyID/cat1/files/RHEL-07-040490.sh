#!/bin/bash
#
# Finding ID:	RHEL-07-040490
# Version:	RHEL-07-040490_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	high
#
# Rule Summary:
#	A File Transfer Protocol (FTP) server package must not be
#	installed unless needed.
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
diag_out "STIG Finding ID: RHEL-07-040490"
diag_out "   No File Transfer Protocol (FTP)"
diag_out "   server packages may be installed"
diag_out "   unless needed."
diag_out "----------------------------------------"

