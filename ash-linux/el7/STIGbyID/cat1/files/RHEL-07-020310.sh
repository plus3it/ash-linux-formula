#!/bin/bash
#
# Finding ID:	RHEL-07-020310
# Version:	RHEL-07-020310_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	high
#
# Rule Summary:
#	The root account must be the only account having
#	unrestricted access to the system.
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
diag_out "STIG Finding ID: RHEL-07-020310"
diag_out "   The root account must be the only"
diag_out "   account having unrestricted access to"
diag_out "   the system."
diag_out "----------------------------------------"

