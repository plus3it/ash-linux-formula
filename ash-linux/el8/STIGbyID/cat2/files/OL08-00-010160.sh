#!/bin/bash
#
# Ref Doc:    STIG - Oracle Linux 8 v1r4
# Finding ID: V-248544
# Rule ID:    SV-248544r818611_rule
# STIG ID:    OL08-00-010160
# SRG ID:     SRG-OS-000120-GPOS-00061
#
# Finding Level: medium
#
# Rule Summary:
#       The OL8 operating system "pam_unix.so" module must be configured in
#       the password-auth file to use a FIPS 140-2 approved cryptographic
#       hashing algorithm for system authentication.
#
# References:
#   CCI:
#     - CCI-000803
#   NIST SP 800-53 :: IA-7
#   NIST SP 800-53A :: IA-7.1
#   NIST SP 800-53 Revision 4 :: IA-7
#
###########################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "--------------------------------------"
diag_out "STIG Finding ID: V-248544"
diag_out "     SHA512 password hashing must be"
diag_out "     enforced through the PAM system's"
diag_out "     /etc/pam.d/password-auth file"
diag_out "--------------------------------------"
