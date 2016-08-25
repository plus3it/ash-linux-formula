#!/bin/bash
#
# Finding ID:	RHEL-07-020152
# Version:	RHEL-07-020152_rule
# SRG ID:	SRG-OS-000366-GPOS-00153
# Finding Level:	high
# 
# Rule Summary:
#	The operating system must prevent the installation of 
#	software, patches, service packs, device drivers, or operating 
#	system components of packages without verification of the 
#	repository metadata.
#
# CCI-001749 
#    NIST SP 800-53 Revision 4 :: CM-5 (3) 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-020152"
diag_out "   The operating system must be"
diag_out "   configured to verify repository"
diag_out "   metadata"
diag_out "----------------------------------------"
