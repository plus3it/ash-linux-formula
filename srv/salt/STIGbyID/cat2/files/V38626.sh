#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38626
# Finding ID:	V-38626
# Version:	RHEL-06-000253
# Finding Level:	Medium
#
#     The LDAP client must use a TLS connection using trust certificates 
#     signed by the site CA. The tls_cacertdir or tls_cacertfile directives 
#     are required when tls_checkpeer is configured (which is the default 
#     for openldap versions 2.1 and up). These directives define the path 
#     to the trust ...
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38626"
diag_out "  LDAP client TLS connections must"
diag_out "  only use certificates signed by"
diag_out "  trusted CAs"
diag_out "----------------------------------"
