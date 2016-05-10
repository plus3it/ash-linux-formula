#!/bin/sh
#
# STIG URL:
# Finding ID:	RHEL-07-021520
# Version:	RHEL-07-021520_rule
# SRG ID:	
# Finding Level:	low
#
# Rule Summary:
#     The Network File System (NFS) export configuration file must 
#     have mode 0644 or less permissive.
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

diag_out "---------------------------------------------"
diag_out "STIG Finding ID: RHEL-07-021520"
diag_out "   Ensure that /etc/exports file has mode"
diag_out "   0644 or less permissive."
diag_out "---------------------------------------------"
