#!/bin/sh
# Finding ID:	RHEL-07-040740
# Version:	RHEL-07-040740_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	The Network File System (NFS) must be configured to use AUTH_GSS.
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
diag_out "STIG Finding ID: RHEL-07-040740"
diag_out "   The Network File System (NFS) must"
diag_out "   be configured to use AUTH_GSS."
diag_out "----------------------------------------"
