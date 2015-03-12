#!/bin/sh
#
# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Rule ID: audit_manual_logon_edits
# - service_acpid_disabled
#
# Security identifiers:
# - CCE-27061-1
#
# Rule Summary: Disable Advanced Configuration and Power Interface (acpid)
#
# Rule Text: The Advanced Configuration and Power Interface Daemon 
#            (acpid) dispatches ACPI events (such as power/reset button 
#            depressed) to userspace programs. ACPI support is highly 
#            desirable for systems in some network roles, such as 
#            laptops or desktops. For other systems, such as servers, it 
#            may permit accidental or trivially achievable denial of 
#            service situations and disabling it is appropriate.
#
#################################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "SCAP Recommendation: "
diag_out "  Disable ACPI service"
diag_out "NOTE: Not yet accepted into STIGs"
diag_out "----------------------------------"

