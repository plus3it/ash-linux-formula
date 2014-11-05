#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38487
# Finding ID:	V-38487
# Version:	RHEL-06-000015
# Finding Level:	Low
#
#     The system package management tool must cryptographically verify the 
#     authenticity of all software packages during installation. Ensuring 
#     all packages' cryptographic signatures are valid prior to 
#     installation ensures the provenance of the software and protects 
#     against malicious tampering.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38487"
diag_out "  Package-management tool must"
diag_out "  verify all packages authenticity"
diag_out "----------------------------------"
