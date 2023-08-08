#!/bin/bash
#
# Ref Doc:    STIG - RHEL 8 v1r10
# Finding ID: V-230333
#             V-230335
#             V-230337
#             V-230341
#             V-230343
#             V-244533
#             V-244534
#             V-244540
# Rule ID:    SV-230333r743966_rule
#             SV-230335r743969_rule
#             SV-230337r743972_rule
#             SV-230341r743978_rule
#             SV-230343r743981_rule
#             SV-244533r743848_rule
#             SV-244534r743851_rule
#             SV-245540r754730_rule
# STIG ID:    RHEL-08-010001
#             RHEL-08-020011
#             RHEL-08-020013
#             RHEL-08-020015
#             RHEL-08-020019
#             RHEL-08-020021
#             RHEL-08-020025
#             RHEL-08-020026
# SRG ID:     SRG-OS-000021-GPOS-00005
#             SRG-OS-000191-GPOS-00080
#
# Finding Level: medium
#
# Rule Summary:
#       The OS must lock out user accounts after a three failures within a
#       fifteen minute interval. The account should stay locked until an
#       administrator manually unlocks the account.
#
# References:
#   CCI:
#     - CCI-000044
#       - NIST SP 800-53 :: AC-7 a
#       - NIST SP 800-53A :: AC-7.1 (ii)
#       - NIST SP 800-53 Revision 4 :: AC-7 a
#     - CCI-001233
#       - NIST SP 800-53 :: SI-2 (2)
#       - NIST SP 800-53A :: SI-2 (2).1 (ii)
#       - NIST SP 800-53 Revision 4 :: SI-2 (2)
#
###########################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "--------------------------------------"
diag_out "STIG Finding ID: (Multiple)"
diag_out "     OS must lock user accounts after"
diag_out "     three failures in fifteen minutes"
diag_out "--------------------------------------"
