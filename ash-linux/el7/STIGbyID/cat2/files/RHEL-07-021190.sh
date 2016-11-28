#!/bin/sh
# Finding ID:	RHEL-07-021190
# Version:	RHEL-07-021190_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	If the cron.allow file exists it must be owned by root.
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
diag_out "STIG Finding ID: RHEL-07-021190"
diag_out "   If the cron.allow file exists it"
diag_out "   must be owned by root."
diag_out "----------------------------------------"
