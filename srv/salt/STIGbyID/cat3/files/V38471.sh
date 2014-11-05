#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38471
# Finding ID:	V-38471
# Version:	RHEL-06-000509
# Finding Level:	Low
#
#     The auditd service does not include the ability to send audit records 
#     to a centralized server for management directly. It does, however, 
#     include an audit event multiplexor plugin (audispd) to pass audit 
#     records to the local syslog server. 
#
#  CCI: CCI-000136
#  NIST SP 800-53 :: AU-3 (2)
#  NIST SP 800-53A :: AU-3 (2).1 (ii)
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38471"
diag_out "  The audit service should forward"
diag_out "  records to the syslog service"
diag_out "----------------------------------"
