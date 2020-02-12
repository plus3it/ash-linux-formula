#!/bin/sh
# Finding ID:	RHEL-07-030010
# Version:	RHEL-07-030010_rule
# SRG ID:	SRG-OS-000046-GPOS-00022
# Finding Level:	medium
# 
# Rule Summary:
#	The operating system must shut down upon audit processing
#	failure, unless availability is an overriding concern. If
#	availability is a concern, the system must alert the
#	designated staff (System Administrator [SA] and Information
#	System Security Officer [ISSO] at a minimum) in the event of
#	an audit processing failure.
#
# CCI-000139 
#    NIST SP 800-53 :: AU-5 a 
#    NIST SP 800-53A :: AU-5.1 (ii) 
#    NIST SP 800-53 Revision 4 :: AU-5 a 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-030010"
diag_out "   The operating system must shut down"
diag_out "   upon audit processing failure,"
diag_out "   unless availability is an overriding"
diag_out "   concern."
diag_out "----------------------------------------"
