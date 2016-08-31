#!/bin/bash
#
# Finding ID:	RHEL-07-020170
# Version:	RHEL-07-020170_rule
# SRG ID:	SRG-OS-000405-GPOS-00184
# Finding Level:	high
#
# Rule Summary:
#	Operating systems handling data requiring data-at-rest
#	protections must employ cryptographic mechanisms to prevent
#	unauthorized disclosure and modification of the information
#	at rest.
#
# CCI-002476
# CCI-001199
#    NIST SP 800-53 Revision 4 :: SC-28 (1)
#    NIST SP 800-53 :: SC-28
#    NIST SP 800-53A :: SC-28.1
#    NIST SP 800-53 Revision 4 :: SC-28
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-020170"
diag_out "   Where applicable, operating should be"
diag_out "   configured to provide data-at-rest"
diag_out "   protection via storage-encryption."
diag_out "----------------------------------------"
