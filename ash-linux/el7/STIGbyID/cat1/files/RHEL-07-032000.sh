#!/bin/bash
#
# Finding ID:	RHEL-07-032000
# Version:	RHEL-07-032000_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	high
# 
# Rule Summary:
#	The system must use a DoD-approved virus scan program.
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
diag_out "STIG Finding ID: RHEL-07-032000"
diag_out "   The system must use a DoD-approved"
diag_out "   virus scan program."
diag_out "----------------------------------------"

