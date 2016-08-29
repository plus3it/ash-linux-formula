#!/bin/bash
#
# Finding ID:	RHEL-07-021280
# Version:	RHEL-07-021280_rule
# SRG ID:	SRG-OS-000033-GPOS-00014
# Finding Level:	high
#
# Rule Summary:
#	The operating system must implement NIST FIPS-validated
#	cryptography for the following: to provision digital
#	signatures, to generate cryptographic hashes, and to protect
#	unclassified information requiring confidentiality and
#	cryptographic protection in accordance with applicable federal
#	laws, Executive Orders, directives, policies, regulations, and
#	standards.
#
# CCI-000068
# CCI-002450
#    NIST SP 800-53 :: AC-17 (2)
#    NIST SP 800-53A :: AC-17 (2).1
#    NIST SP 800-53 Revision 4 :: AC-17 (2)
#    NIST SP 800-53 Revision 4 :: SC-13
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-021280"
diag_out "   The operating system must implement"
diag_out "   NIST FIPS-validated cryptography."
diag_out "----------------------------------------"
