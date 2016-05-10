#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38520
# Finding ID:	V-38520
# Version:	RHEL-06-000136
# Finding Level:	Medium
#
#     The operating system must back up audit records on an organization 
#     defined frequency onto a different system or media than the system 
#     being audited. A log server (loghost) receives syslog messages from 
#     one or more systems. This data can be used as an additional log 
#     source in the event a system is compromised and its local logs are 
#     suspect. ...
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38520"
diag_out "  The rsyslog service must be"
diag_out "  configured send copies of log"
diag_out "  entires to a remote"
diag_out "  collection-node"
diag_out "----------------------------------"
