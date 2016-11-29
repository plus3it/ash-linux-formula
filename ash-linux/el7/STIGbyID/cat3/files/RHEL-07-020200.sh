#!/bin/bash
#
# Finding ID:	RHEL-07-020200
# Version:	RHEL-07-020200_rule
# SRG ID:	SRG-OS-000437-GPOS-00194
# Finding Level:	low
# 
# Rule Summary:
#	The operating system must remove all software components
#	after updated versions have been installed.
#
# CCI-002617 
#    NIST SP 800-53 Revision 4 :: SI-2 (6) 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-020200"
diag_out "   The operating system must remove all"
diag_out "   software components after updated"
diag_out "   versions have been installed."
diag_out "----------------------------------------"
