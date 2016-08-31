#!/bin/bash
#
# Finding ID:	RHEL-07-030010
# Version:	RHEL-07-030010_rule
# SRG ID:	SRG-OS-000038-GPOS-00016
# Finding Level:	high
#
# Rule Summary:
#	Auditing must be configured to produce records containing
#	information to establish what type of events occurred, where the
#	events occurred, the source of the events, and the outcome of
#	the events. These audit records must also identify individual
#	identities of group account users.
#
# CCI-000131
# CCI-000126
#    NIST SP 800-53 :: AU-3
#    NIST SP 800-53A :: AU-3.1
#    NIST SP 800-53 Revision 4 :: AU-3
#    NIST SP 800-53 :: AU-2 d
#    NIST SP 800-53A :: AU-2.1 (v)
#    NIST SP 800-53 Revision 4 :: AU-2 d
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-030010"
diag_out "   Auditing service must be running."
diag_out "----------------------------------------"
