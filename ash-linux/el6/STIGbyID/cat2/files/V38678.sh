#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38678
# Finding ID:	V-38678
# Version:	RHEL-06-000311
# Finding Level:	Medium
#
#     The audit system must provide a warning when allocated audit record 
#     storage volume reaches a documented percentage of maximum audit 
#     record storage capacity. Notifying administrators of an impending 
#     disk space problem may allow them to take corrective action prior to 
#     any disruption.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38678"
diag_out "  audit system sends an alert when"
diag_out "  policy-defined storage-capacity"
diag_out "  threshold is reached"
diag_out "----------------------------------"

