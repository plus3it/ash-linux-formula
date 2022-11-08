#!/bin/sh
#
# Finding ID:
# Versions:
#   - mount_option_boot.sls
# SRG ID:
# Finding Level:	medium
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
#   - FMT_SMF_EXT.1
#   - FMT_MOF_EXT.1
#   - FTA_SSL.1
#   - SRG-OS-000031-GPOS-00012
#   - SRG-OS-000028-GPOS-00009
#   - SRG-OS-000030-GPOS-00011
#   - RHEL-08-020041
#   - SV-230349r810020_rule
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

