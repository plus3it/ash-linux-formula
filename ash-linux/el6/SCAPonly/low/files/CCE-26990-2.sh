#!/bin/sh
#
# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Rule ID: audit_manual_logon_edits
# - service_irqbalance_enabled
#
# Security identifiers:
# - CCE-26990-2
#
# Rule Summary: Enable IRQ Balance (irqbalance)
#
# Rule Text: The irqbalance service optimizes the balance between power 
#            savings and performance through distribution of hardware 
#            interrupts across multiple processors.  In an environment 
#            with multiple processors (now common), the irqbalance 
#            service provides potential speedups for handling interrupt 
#            requests (helpful in systems with enhanced audit-collection 
#            enabled).
#
#################################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "SCAP Recommendation: "
diag_out "  Enable the 'irqbalance' service."
diag_out "NOTE: Not yet accepted into STIGs"
diag_out "----------------------------------"

