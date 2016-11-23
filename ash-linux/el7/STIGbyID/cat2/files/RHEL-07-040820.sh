#!/bin/sh
# Finding ID:	RHEL-07-040820
# Version:	RHEL-07-040820_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	The system's access control program must be configured to grant
#	or deny system access to specific hosts and services.
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
diag_out "STIG Finding ID: RHEL-07-040820"
diag_out "   The system's access control program"
diag_out "   must be configured to grant or deny"
diag_out "   system access to specific hosts and"
diag_out "   services."
diag_out "----------------------------------------"
