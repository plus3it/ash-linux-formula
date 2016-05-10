#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38595
# Finding ID:	V-38595
# Version:	RHEL-06-000349
# Finding Level:	Medium
#
#     The system must be configured to require the use of a CAC, PIV 
#     compliant hardware token, or Alternate Logon Token (ALT) for 
#     authentication. Smart card login provides two-factor authentication 
#     stronger than that provided by a username/password combination. Smart 
#     cards leverage a PKI (public key infrastructure) in order to provide 
#     and ...
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38595"
diag_out "  Determine if system access is"
diag_out "  configured to require CAC-based"
diag_out "  authentication"
diag_out "----------------------------------"
