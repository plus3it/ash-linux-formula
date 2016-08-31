#!/bin/bash
#
# Finding ID:	RHEL-07-020210
# Version:	RHEL-07-020210_rule
# SRG ID:	SRG-OS-000445-GPOS-00199
# Finding Level:	high
#
# Rule Summary:
#	The operating system must enable SELinux.
#
# CCI-002165
# CCI-002696
#    NIST SP 800-53 Revision 4 :: AC-3 (4)
#    NIST SP 800-53 Revision 4 :: SI-6 a
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-020210"
diag_out "   The operating system must enable"
diag_out "   SELinux."
diag_out "----------------------------------------"

