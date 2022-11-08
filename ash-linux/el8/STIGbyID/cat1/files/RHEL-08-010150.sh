# Ref Doc:    STIG - RHEL 9 v1r7
# Finding ID: V-230235
# STIG ID:    RHEL-08-010150
# Rule ID:    SV-230235r743925_rule
# SRG ID(s):  SRG-OS-000080-GPOS-00048
# Finding Level:        high
#
# Rule Summary:
#       RHEL 8 operating systems booted with a BIOS must
#       require authentication upon booting into
#       single-user and maintenance modes
#
# References:
#   CCI:
#     - CCI-000213
#   NIST SP 800-53 :: AC-3
#   NIST SP 800-53A :: AC-3.1
#   NIST SP 800-53 Revision 4 :: AC-3
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "--------------------------------------"
diag_out "STIG Finding ID: V-230235"
diag_out "     RHEL 8 must require authenticated"
diag_out "     user in order to access single-"
diag_out "     user and maintenance modes"
diag_out "--------------------------------------"
