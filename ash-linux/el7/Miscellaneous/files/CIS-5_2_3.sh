#!/bin/bash
#
# Rule Name:    sshd_set_loglevel_info
# CIS Rule ID:  5.2.3
#
# Summary:
#
#    SSH provides several logging levels with varying amounts of
#    verbosity. DEBUG is specifically not recommended other than
#    strictly for debugging SSH communications since it provides
#    so much data that it is difficult to identify important
#    security information. INFO level is the basic level that
#    only records login activity of SSH users. In many
#    situations, such as Incident Response, it is important to
#    determine when a particular user was active on a system. The
#    logout record can eliminate those users who disconnected,
#    which helps narrow the field.
#
#    Note: The EL7 SSHD defaults the value for the LogLevel 
#    parameter to be `Info`. This state is simply designed to
#    help reduce false alerts caused by scan profiles that fail
#    to properly identify this defaulted posture.
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "CIS Benchmark ID: 5.2.3"
diag_out "   Configure SSHD to log all activities"
diag_out "   at the 'Info' level (minimum)"
diag_out "----------------------------------------"

