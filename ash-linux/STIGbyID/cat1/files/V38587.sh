#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38587
# Finding ID:	V-38587
# Version:	RHEL-06-000206
# Finding Level:	High
#
#     The telnet-server package must not be installed. Removing the 
#     "telnet-server" package decreases the risk of the unencrypted telnet 
#     service's accidental (or intentional) activation.  Mitigation: If
#     the telnet-server package is configured to only allow encrypted 
#     sessions, such as with Kerberos or the use of encrypted network 
#     tunnels, the risk of exposing sensitive information is mitigated. 
#
############################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38587"
diag_out "  Ensure telnet daemon is not"
diag_out "  installed"
diag_out "----------------------------------"

