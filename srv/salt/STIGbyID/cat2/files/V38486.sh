#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38486
# Finding ID:	V-38486
# Version:	RHEL-06-000505
# Finding Level:	Medium
#
#     The operating system must conduct backups of system-level information 
#     contained in the information system per organization defined 
#     frequency to conduct backups that are consistent with recovery time 
#     and recovery point objectives. Operating system backup is a critical 
#     step in maintaining data assurance and availability. System-level 
#     information includes system-state information, operating system and 
#     application software, and ...
#
############################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "  Ascertain if system is protected"
diag_out "  through backups of both config"
diag_out "  and application data"
diag_out "----------------------------------"
