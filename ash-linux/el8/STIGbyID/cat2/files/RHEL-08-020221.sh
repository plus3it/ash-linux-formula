# Ref Doc:    STIG - RHEL 9 v1r7
# Finding ID: V-230368
# Rule ID:    SV-230368r810414_rule
# STIG ID:    RHEL-08-020221
# SRG ID:     SRG-OS-000077-GPOS-00045
#
# Finding Level: medium
#
# Rule Summary:
#       RHEL 8 must be configured in the password-auth file to prohibit
#       password reuse for a minimum of five generations.
#
# References:
#   CCI:
#     - CCI-000200
#   NIST SP 800-53 :: IA-5 (1) (e)
#   NIST SP 800-53A :: IA-5 (1).1 (v)
#   NIST SP 800-53 Revision 4 :: IA-5 (1) (e)
#
###########################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "--------------------------------------"
diag_out "STIG Finding ID: V-251717"
diag_out "     The OS must be configure to"
diag_out "     prohibit password reuse for a"
diag_out "     minimum of five generations"
diag_out "--------------------------------------"
~

