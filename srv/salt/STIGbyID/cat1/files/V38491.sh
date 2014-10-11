#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38491
# Finding ID:	V-38491
# Version:	RHEL-06-000019
# Finding Level:	High
#
#     There must be no .rhosts or hosts.equiv files on the system. Trust 
#     files are convenient, but when used in conjunction with the 
#     R-services, they can allow unauthenticated access to a system.
#
############################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38491"
diag_out "  Find and Delete rhost-related"
diag_out "  files: /etc/hosts.equiv"
diag_out "         ${HOME}/.rhosts"
diag_out "----------------------------------"

