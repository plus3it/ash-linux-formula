#!/bin/sh
#
# STIG URL:
# Finding ID:	RHEL-07-030760
# Version:	RHEL-07-030760_rule
# SRG ID:	
# Finding Level:	low
#
# Rule Summary:
#     xinetd logging/tracing must be enabled via rsyslog.
#
# CCI-000366
#    NIST SP 800-53 :: CM-6 b
#    NIST SP 800-53A :: CM-6.1 (iv)
#    NIST SP 800-53 Revision 4 :: CM-6 b
#
#################################################################

diag_out() {
   echo "${1}"
}

diag_out "---------------------------------------------"
diag_out "STIG Finding ID: RHEL-07-030760"
diag_out "   Configure xinetd to log via rsyslogd if"
diag_out "   the xinetd package is installed."
diag_out "---------------------------------------------"
