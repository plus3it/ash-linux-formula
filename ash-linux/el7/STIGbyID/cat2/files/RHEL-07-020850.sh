#!/bin/sh
# Finding ID:	RHEL-07-020850
# Version:	RHEL-07-020850_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	Local initialization files for local interactive users must be
#	group-owned by the users primary group or root.
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
diag_out "STIG Finding ID: RHEL-07-020850"
diag_out "   Local initialization files for local"
diag_out "   interactive users must be"
diag_out "   group-owned by the users primary"
diag_out "   group or root."
diag_out "----------------------------------------"
