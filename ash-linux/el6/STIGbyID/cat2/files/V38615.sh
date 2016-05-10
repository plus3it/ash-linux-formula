#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38615
# Finding ID:	V-38615
# Version:	RHEL-06-000240
# Finding Level:	Medium
#
#     The SSH daemon must be configured with the Department of Defense 
#     (DoD) login banner. The warning message reinforces policy awareness 
#     during the logon process and facilitates possible legal action 
#     against attackers. Alternatively, systems whose ownership should not 
#     be obvious should ...
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38615"
diag_out "  SSH daemon must be configured to"
diag_out "  present DoD login banner"
diag_out "----------------------------------"
