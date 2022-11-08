# Ref Doc:    STIG - RHEL 9 v1r7
# Finding ID: V-230470
# Rule ID:    SV-230470r744006_rule
# STIG ID:    RHEL-08-030603
# SRG ID:     SRG-OS-000062-GPOS-00031
#
# Finding Level: low
#
# Rule Summary:
#       The OS must enable Linux audit logging for the USBGuard daemon
#
# References:
#   CCI:
#     - CCI-000169
#   NIST SP 800-53 :: AU-12 a
#   NIST SP 800-53A :: AU-12.1 (ii)
#   NIST SP 800-53 Revision 4 :: AU-12 a
#
###########################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "--------------------------------------"
diag_out "STIG Finding ID: V-230470"
diag_out "    The OS must enable Linux audit"
diag_out "    logging for the USBGuard daemon"
diag_out "--------------------------------------"
