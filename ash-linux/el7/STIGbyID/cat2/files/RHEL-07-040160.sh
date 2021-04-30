#!/bin/sh
# Finding ID:	RHEL-07-040160
# Version:	RHEL-07-040160_rule
# SRG ID:	SRG-OS-000163-GPOS-00072
# Finding Level:	medium
#
# Rule Summary:
#	All network connections associated with a communication
#	session must be terminated at the end of the session or after
#	10 minutes of inactivity from the user at a command prompt,
#	except to fulfill documented and validated mission
#	requirements.
#
# CCI-001133
# CCI-002361
#    NIST SP 800-53 :: SC-10
#    NIST SP 800-53A :: SC-10.1 (ii)
#    NIST SP 800-53 Revision 4 :: SC-10
#    NIST SP 800-53 Revision 4 :: AC-12
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-040160"
diag_out "   All network connections associated"
diag_out "   with a communication session must be"
diag_out "   terminated at the end of the session"
diag_out "   or after 10 minutes of inactivity"
diag_out "   from the user at a command prompt,"
diag_out "   except to fulfill documented and"
diag_out "   validated mission requirements."
diag_out "----------------------------------------"
