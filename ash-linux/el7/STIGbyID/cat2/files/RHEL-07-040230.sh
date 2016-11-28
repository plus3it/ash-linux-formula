#!/bin/sh
# Finding ID:	RHEL-07-040230
# Version:	RHEL-07-040230_rule
# SRG ID:	SRG-OS-000384-GPOS-00167
# Finding Level:	medium
# 
# Rule Summary:
#	The operating system, if using PKI-based authentication, must
#	implement a local cache of revocation data to certificate
#	validation in case of the inability to access revocation
#	information via the network.
#
# CCI-001991 
#    NIST SP 800-53 Revision 4 :: IA-5 (2) (d) 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-040230"
diag_out "----------------------------------------"
