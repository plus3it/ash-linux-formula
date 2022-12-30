#!/bin/sh
# Ref Doc:    STIG - RHEL 8 v1r7
# Finding ID: V-230349
# STIG ID:    RHEL-08-020041
# Rule ID:    SV-230349r833388_rule
# SRG ID:     SRG-OS-000028-GPOS-00009
#
# Finding Level: medium
#
# Rule Summary:
#       The tmux terminal multiplexer is used to implement automatic
#       session locking. It should be started for every interactive
#       login-shell
#
# Identifiers:
#   - CCE-82266-8
#
# References:
#   - CCI-000056
#   - CCI-000058
#
# NIST SP 800-53 :: AC-11 b
# NIST SP 800-53A :: AC-11.1 (iii)
# NIST SP 800-53 Revision 4 :: AC-11 b
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "-------------------------------------------"
diag_out "STIG Finding ID: configure_bashrc_exec_tmux"
diag_out "   The tmux terminal multiplexer is used to"
diag_out "   implement automatic session locking. It"
diag_out "   should be started for every interactive"
diag_out "   login-shell."
diag_out "-------------------------------------------"

