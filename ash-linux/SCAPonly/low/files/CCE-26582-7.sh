#!/bin/sh
#
# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Security identifiers:
# - CCE-26582-7
#
# Rule ID: mount_option_var_tmp_bind_var
#
# Rule Summary: Bind Mount /var/tmp To /tmp
#
# Rule Text: Having multiple locations for temporary storage is not 
#            required. Unless absolutely necessary to meet requirements, 
#            the storage location /var/tmp should be bind mounted to 
#            /tmp and thus share the same protections.
#
#            The /var/tmp directory is a world-writable directory. 
#            Bind-mount it to /tmp in order to consolidate temporary 
#            storage into one location protected by the same techniques 
#            as /tmp.
#
#################################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "SCAP Recommendation: "
diag_out "  Bind-mount /tmp to /var/tmp"
diag_out "  so that /var/tmp inherits the"
diag_out "  security settings used for /tmp"
diag_out "NOTE: Not yet accepted into STIGs"
diag_out "----------------------------------"
