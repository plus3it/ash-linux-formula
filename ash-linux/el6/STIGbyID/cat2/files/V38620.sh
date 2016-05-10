#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38620
# Finding ID:	V-38620
# Version:	RHEL-06-000247
# Finding Level:	Medium
#
#     Enabling the "ntpd" service ensures that the "ntpd" service will be 
#     running and that the system will synchronize its time to any servers 
#     specified. This is important whether the system is configured to be a 
#     client (and synchronize only its own clock) or it is also acting as 
#     an NTP server to other systems. Synchronizing time is essential for 
#     authentication services such as Kerberos, but it is also important 
#     for maintaining accurate logs and auditing possible security breaches.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38620"
diag_out "  The system clock must be"
diag_out "  synchronized on a continual (or"
diag_out "  at least daily) basis"
diag_out "----------------------------------"
