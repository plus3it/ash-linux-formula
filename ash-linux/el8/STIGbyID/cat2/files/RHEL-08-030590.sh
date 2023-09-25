#!/bin/bash
# Ref Doc:    STIG - RHEL 8 v1r11
# Finding ID: V-230466
# Rule ID:    SV-230466r627750_rule
# STIG ID:    RHEL-08-030590
# SRG ID:     SRG-OS-000037-GPOS-00015
#             SRG-OS-000042-GPOS-00020
#             SRG-OS-000062-GPOS-00031
#             SRG-OS-000062-GPOS-00031
#             SRG-OS-000392-GPOS-00172
#             SRG-OS-000462-GPOS-00206
#             SRG-OS-000471-GPOS-00215
#             SRG-OS-000473-GPOS-00218
#
# Finding Level: medium
#
# Rule Summary:
#       Successful/unsuccessful modifications to the faillock log file
#       in RHEL 8 must generate an audit record.
#
# References:
#   CCI:
#     - CCI-000169
#         NIST SP 800-53 :: AU-12 a
#         NIST SP 800-53A :: AU-12.1 (ii)
#         NIST SP 800-53 Revision 4 :: AU-12 a
#
###########################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "--------------------------------------"
diag_out "STIG Finding ID: V-230466"
diag_out "     Modifications to the faillock log"
diag_out "     file must generate an audit"
diag_out "     record"
diag_out "--------------------------------------"
