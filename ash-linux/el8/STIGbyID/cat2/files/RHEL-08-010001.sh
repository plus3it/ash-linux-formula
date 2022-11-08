# Ref Doc:    STIG - RHEL 9 v1r7
# Finding ID: V-245540
# Rule ID:    SV-245540r754730_rule
# STIG ID:    RHEL-08-010001
# SRG ID:     SRG-OS-000191-GPOS-00080
#
# Finding Level: medium
#
# Rule Summary:
#       The EL8 operating system must implement the Endpoint Security
#       for Linux Threat Prevention tool.
#
# References:
#   CCI:
#     - CCI-001233
#   NIST SP 800-53 :: SI-2 (2)
#   NIST SP 800-53A :: SI-2 (2).1 (ii)
#   NIST SP 800-53 Revision 4 :: SI-2 (2)
#
###########################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "--------------------------------------"
diag_out "STIG Finding ID: V-245540"
diag_out "     The OS must implement the"
diag_out "     Endpoint Security for Linux"
diag_out "     Threat Prevention tool"
diag_out "--------------------------------------"
