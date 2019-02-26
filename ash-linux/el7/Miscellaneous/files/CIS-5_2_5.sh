#!/bin/bash
# Rule Name:    sshd_set_max_auth_tries
# CIS Rule ID:  5.2.5
#
# Summary:
#
#    The MaxAuthTries parameter specifies the maximum number of
#    authentication attempts permitted per connection. When the
#    login failure count reaches half the number, error messages
#    will be written to the syslog file detailing the login
#    failure.
#
#    Setting the MaxAuthTries parameter to a low number will
#    minimize the risk of successful brute force attacks to the
#    SSH server. While the recommended setting is 4, set the
#    number based on site policy.
#
#    Note: Mostly obviated by the STIG-mandated modifications to
#    the PAM subsystem. Included for scanners that include CIS-
#    recommended settings that are not part of the STIGs
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "CIS Benchmark ID: 5.2.5"
diag_out "   Configure SSHD to limit number of"
diag_out "   failed authentication attempts."
diag_out "----------------------------------------"

