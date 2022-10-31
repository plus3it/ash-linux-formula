# Ref Doc:    STIG - RHEL 9 v1r7
# Finding ID: V-230327
# STIG ID:    RHEL-08-010790
# Rule ID:    SV-230327r627750_rule
# SRG ID:     SRG-OS-000480-GPOS-00227
#
# Finding Level: medium
#
# Rule Summary:
#	All local files and directories must have a valid group owner.
#
# CCI-002165
#  - CCI-000366
#
# NIST SP 800-53 :: CM-6 b
# NIST SP 800-53A :: CM-6.1 (iv)
# NIST SP 800-53 Revision 4 :: CM-6 b#
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "--------------------------------------"
diag_out "STIG Finding ID: V-230327"
diag_out "     All local files and directories"
diag_out "     must have a valid group owner"
diag_out "--------------------------------------"
