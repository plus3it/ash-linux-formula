# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Rule ID: audit_manual_logon_edits
# - audit_manual_session_edits
#
# Security identifiers:
# - CCE-26610-6
#
# Rule Summary: Record Attempts to Alter Process and Session
#               Initiation Information
#
# Rule Text: The audit system already collects process information for 
#            all users and root. This data is stored in the 
#            '/var/run/utmp', '/var/log/btmp' and '/var/log/wtmp' files. 
#            Manual editing of these files may indicate nefarious 
#            activity, such as an attacker attempting to remove evidence 
#            of an intrusion. Configure the audit subsystem to monitor 
#            these files.
#
#################################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "SCAP Recommendation: "
diag_out "  Audit attempts to edit session-"
diag_out "  tracking files"
diag_out "NOTE: Not yet accepted into STIGs"
diag_out "----------------------------------"

