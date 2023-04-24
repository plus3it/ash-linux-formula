# Ref Doc:    STIG - RHEL 8 v1r7
# Finding ID: V-230350
# Rule ID:    SV-230350r627750_rule
# STIG ID:    RHEL-08-020042
# SRG ID:     SRG-OS-000028-GPOS-00009
#
# Finding Level: low
#
# Rule Summary:
#       The OS must prevent users from disabling session control
#       mechanisms.
#
# References:
#   CCI:
#     - CCI-000056
#   NIST SP 800-53 :: AC-11 b
#   NIST SP 800-53A :: AC-11.1 (iii)
#   NIST SP 800-53 Revision 4 :: AC-11 b
#
###########################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "--------------------------------------"
diag_out "STIG Finding ID: V-230350"
diag_out "    The OS must prevent users diag_out"
diag_out "    from disabling session control"
diag_out "    mechanisms."
diag_out "--------------------------------------"
diag_out ""
diag_out "changed=no"
