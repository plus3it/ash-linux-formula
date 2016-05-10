#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38476
# Finding ID:	V-38476
# Version:	RHEL-06-000008
# Finding Level:	High
#
#     Vendor-provided cryptographic certificates must be installed to 
#     verify the integrity of system software. The Red Hat GPG key is 
#     necessary to cryptographically verify packages are from Red Hat.
#
############################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38476"
diag_out "  Ensure vendor-provided RPM"
diag_out "  signing-keys are installed"
diag_out "----------------------------------"

