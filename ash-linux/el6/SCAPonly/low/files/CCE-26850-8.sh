#!/bin/sh
#
# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Rule ID: audit_manual_logon_edits
# - service_kdump_disabled
#
# Security identifiers:
# - CCE-26850-8
#
# Rule Summary: Disable KDump Kernel Crash Analyzer (kdump)
#
# Rule Text: The kdump service provides a kernel crash dump analyzer. It 
#            uses the kexec system call to boot a secondary kernel 
#            ("capture" kernel) following a system crash, which can load 
#            information from the crashed kernel for analysis. On 
#            systems processing sensitive information, this can allow 
#            sensitive information to be stored in unwanted locations. 
#            Unless the system is used for kernel development, testing,  
#            there is little need to run the kdump service (e.g., 
#            production systems should only ever *temporarily* enable it 
#            for use in diagnosis of chronic stability issues).
#
#################################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "SCAP Recommendation: "
diag_out "  Disable kdump service"
diag_out "NOTE: Not yet accepted into STIGs"
diag_out "----------------------------------"

