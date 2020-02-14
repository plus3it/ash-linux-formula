#!/bin/sh
# Finding ID:	RHEL-07-030820
# Version:	RHEL-07-030820_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	The system must update the DoD-approved virus scan program
#	every seven days or more frequently.
#
# CCI-001668 
#    NIST SP 800-53 :: SI-3 a 
#    NIST SP 800-53A :: SI-3.1 (ii) 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-030820"
diag_out "   The system must update the DOD-"
diag_out "   approved virus scan program every"
diag_out "   seven days or more frequently."
diag_out "----------------------------------------"
