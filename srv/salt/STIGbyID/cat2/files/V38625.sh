#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38625
# Finding ID:	V-38625
# Version:	
# Finding Level:	Medium
#
#     If the system is using LDAP for authentication or account 
#     information, the system must use a TLS connection using FIPS 140-2 
#     approved cryptographic algorithms. The ssl directive specifies 
#     whether to use ssl or not. If not specified it will default to "no". 
#     It should be set to "start_tls" rather than doing LDAP over SSL.
#
############################################################

