#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38625
# Finding ID:	V-38625
# Version:	RHEL-06-000252
# Finding Level:	Medium
#
#     If the system is using LDAP for authentication or account 
#     information, the system must use a TLS connection using FIPS 140-2 
#     approved cryptographic algorithms. The ssl directive specifies 
#     whether to use ssl or not. If not specified it will default to "no". 
#     It should be set to "start_tls" rather than doing LDAP over SSL.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38625"
diag_out "  System must use TLS with FIPS"
diag_out "  140-2 compliant ciphers for all"
diag_out "  authentication or account"
diag_out "  informaton transfers"
diag_out "----------------------------------"
