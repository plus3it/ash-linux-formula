#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38483
# Finding ID:	V-38483
# Version:	RHEL-06-000013
# Finding Level:	Medium
#
#     The system package management tool must cryptographically verify the 
#     authenticity of system software packages during installation. 
#     Ensuring the validity of packages' cryptographic signatures prior to 
#     installation ensures the provenance of the software and protects 
#     against malicious tampering.
#
#  CI: CCI-000663
#  NIST SP 800-53 :: SA-7
#  NIST SP 800-53A :: SA-7.1 (ii)
#
############################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38483"
diag_out "  Ensure that GPG-checking is"
diag_out "  enabled in all yum configuration"
diag_out "  files (esp. /etc/yum.conf and)"
diag_out "----------------------------------"
