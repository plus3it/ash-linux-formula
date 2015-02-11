#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38607
# Finding ID:	V-38607
# Version:	RHEL-06-000227
# Finding Level:	High
#
#     The SSH daemon must be configured to use only the SSHv2 protocol. SSH 
#     protocol version 1 suffers from design flaws that result in security 
#     vulnerabilities and should not be used.
#
############################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38607"
diag_out "  The SSH daemon must only use the"
diag_out "  SSHv2 protocol"
diag_out "----------------------------------"

