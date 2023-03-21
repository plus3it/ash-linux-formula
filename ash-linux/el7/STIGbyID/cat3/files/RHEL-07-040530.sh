#!/bin/sh
# Finding ID:	RHEL-07-040530
# Version:	SV-204605r603261_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	low
#
# Rule Summary:
#	The operating system must display the date and time of
#   the last successful account logon upon logon.
#
# CCI-000366
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-040530"
diag_out "   The OS must display date/time of last"
diag_out "   successful account login"
diag_out "----------------------------------------"
