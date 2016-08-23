#!/bin/bash
#
# Finding ID:	RHEL-07-010010
# Version:	RHEL-07-010010_rule
# SRG ID:	SRG-OS-000257-GPOS-00098
# Finding Level:	high
#
# Rule Summary:
#	The file permissions, ownership, and group membership of
#	system files and commands must match the vendor values.
#
# CCI-001494
# CCI-001496
#    NIST SP 800-53 :: AU-9
#    NIST SP 800-53A :: AU-9.1
#    NIST SP 800-53 Revision 4 :: AU-9
#    NIST SP 800-53 :: AU-9 (3)
#    NIST SP 800-53A :: AU-9 (3).1
#    NIST SP 800-53 Revision 4 :: AU-9 (3)
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-010010"
diag_out "   Ensure that all RPM-managed files are"
diag_out "   set to the proper file-mode."
diag_out "----------------------------------------"

