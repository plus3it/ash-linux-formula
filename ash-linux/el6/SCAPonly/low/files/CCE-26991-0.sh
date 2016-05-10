#!/bin/sh
#
# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Rule ID:
# - service_restorecond_enabled
#
# Security identifiers:
# - CCE-26991-0
#
# Rule Summary: Enable the SELinux Context Restoration Service
#
# Rule Text: The restorecond service utilizes inotify to look for the 
#            creation of new files listed in the 
#            /etc/selinux/restorecond.conf configuration file. When a 
#            file is created, restorecond ensures the file receives the 
#            proper SELinux security context. The restorecond service 
#            can be enabled with the following command:
#
#################################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "-----------------------------------"
diag_out "SCAP Recommendation: "
diag_out "  Enable the SELinux Context"
diag_out "  Restoration Service (restorecond)"
diag_out "NOTE: Not yet accepted into STIGs"
diag_out "-----------------------------------"

