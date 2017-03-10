#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38617
# Finding ID:	V-38617
# Version:	RHEL-06-000243
# Finding Level:	Medium
#
#     The SSH daemon must be configured to use only FIPS 140-2 approved 
#     ciphers. Approved algorithms should impart some level of confidence 
#     in their implementation. These are also required for compliance.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38617"
diag_out "  SSH daemon must be configured to"
diag_out "  use only FIPS 140-2 approved"
diag_out "  ciphers"
diag_out "----------------------------------"
