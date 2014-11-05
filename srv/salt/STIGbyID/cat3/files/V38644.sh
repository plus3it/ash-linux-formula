#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38644
# Finding ID:	V-38644
# Version:	RHEL-06-000265
# Finding Level:	Low
#
#     The ntpdate service must not be running. The "ntpdate" service may 
#     only be suitable for systems which are rebooted frequently enough 
#     that clock drift does not cause problems between reboots. In any 
#     event, the functionality of the ntpdate service is now available in 
#     the ntpd program and should be considered deprecated. 
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38644"
diag_out "  The ntpdate service must not be"
diag_out "  running."
diag_out "----------------------------------"
