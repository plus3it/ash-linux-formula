#!/bin/bash
#
# Finding ID:	RHEL-07-040300
# Version:	RHEL-07-040300_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	low
# 
# Rule Summary:
#	The system must display the date and time of the last
#	successful account logon upon logon.
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
diag_out "STIG Finding ID: RHEL-07-040300"
diag_out "   The system must display the date and"
diag_out "   time of the last successful account"
diag_out "   logon upon logon."
diag_out "----------------------------------------"
