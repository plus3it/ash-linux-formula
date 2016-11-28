#!/bin/sh
# Finding ID:	RHEL-07-021050
# Version:	RHEL-07-021050_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	All world-writable directories must be group-owned by root, sys,
#	bin, or an application group.
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
diag_out "STIG Finding ID: RHEL-07-021050"
diag_out "   All world-writable directories must"
diag_out "   be group-owned by root, sys, bin, or"
diag_out "   an application group."
diag_out "----------------------------------------"
