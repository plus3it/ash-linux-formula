#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38621
# Finding ID:	V-38621
# Version:	RHEL-06-000248
# Finding Level:	Medium
#
#     The system clock must be synchronized to an authoritative DoD time 
#     source. Synchronizing with an NTP server makes it possible to collate 
#     system logs from multiple sources or correlate computer events with 
#     real time events. Using a trusted NTP server provided by your ...
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38621"
diag_out "  The system clock must be"
diag_out "  synchronized to an authoritative"
diag_out "  DoD time-source"
diag_out "----------------------------------"
