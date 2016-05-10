#!/bin/sh
# 
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38462
# Finding ID:	V-38462
# Version:	RHEL-06-000514
#
#      Ensuring all packages' cryptographic signatures are valid prior
#      to installation ensures the provenance of the software and
#      protects against malicious tampering. 
#
###########################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38462"
diag_out "  Ensure that rpm utilities verify"
diag_out "  all package signatures' validity"
diag_out "----------------------------------"
