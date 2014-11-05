#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38568
# Finding ID:	V-38568
# Version:	RHEL-06-000199
# Finding Level:	Low
#
#     The audit system must be configured to audit successful file system 
#     mounts. The unauthorized exportation of data to external media could 
#     result in an information leak where classified information, Privacy 
#     Act information, and intellectual property could be lost. An audit 
#     trail should be created each time a filesystem is mounted to help 
#     identify and guard against information loss
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38568"
diag_out "  Audit system must be configured"
diag_out "  to audit successful file system"
diag_out "  mounts"
diag_out "----------------------------------"
