#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38574
# Finding ID:	V-38574
# Version:	RHEL-06-000062
# Finding Level:	Medium
#
#     The system must use a FIPS 140-2 approved cryptographic hashing 
#     algorithm for generating account password hashes (system-auth). Using 
#     a stronger hashing algorithm makes password cracking attacks more 
#     difficult.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38574"
diag_out "  The system must be configured to"
diag_out "  use the SHA512 encryption"
diag_out "  algorithm for locally-managed"
diag_out "  user accounts"
diag_out "----------------------------------"
