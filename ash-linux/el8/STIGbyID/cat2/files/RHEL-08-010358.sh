#!/bin/bash
# Ref Doc:    STIG - RHEL 8 v1r10
# Finding ID: V-256974
# Rule ID:    SV-256974r902755_rule
# STIG ID:    RHEL-08-010358
# SRG ID:     r902755_rule
#
# Finding Level: medium
#
# Rule Summary:
#       RHEL 8 must be configured to allow sending email notifications of
#       unauthorized configuration changes to designated personnel.
#
# References:
#   CCI:
#     - CCI-001744
#   NIST SP 800-53 Revision 4 :: CM-3 (5)
#
###########################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "--------------------------------------"
diag_out "STIG Finding ID: V-256974"
diag_out "     OS must have mailer software"
diag_out "     available for notifiers to use"
diag_out "--------------------------------------"
