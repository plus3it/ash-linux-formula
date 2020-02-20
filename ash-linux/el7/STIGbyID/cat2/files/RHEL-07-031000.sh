#!/bin/sh
# Finding ID:	RHEL-07-031000
# Version:	RHEL-07-031000_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	The system must send rsyslog output to a log aggregation server.
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
diag_out "STIG Finding ID: RHEL-07-031000"
diag_out "   The system must send rsyslog output"
diag_out "   to a log aggregation server."
diag_out "----------------------------------------"
