#!/bin/sh
# 
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38668
# Finding ID:	V-38668 
# Version:	RHEL-06-000286
#
#     A locally logged-in user who presses Ctrl-Alt-Delete, when at the 
#     console, can reboot the system. If accidentally pressed, as could 
#     happen in the case of mixed OS environment, this can create the risk 
#     of short-term loss of availability of systems due to unintentional 
#     reboot. In the GNOME graphical environment, risk of unintentional 
#     reboot from the Ctrl-Alt-Delete sequence is reduced because the user 
#     will be prompted before any action is taken. 
#
###########################################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38668"
diag_out "  Pressing Ctrl-Alt-Delete should"
diag_out "  not reboot the system."
diag_out "----------------------------------"

