# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Rule ID: audit_manual_logon_edits
# - audit_config_immutable
#
# Security identifiers:
# - CCE-26612-2
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
# NOTE 1: This handler *MUST* be run after all other handlers that change
#         the /etc/audit/audit.rules file's contents. If further rules
#         are placed after the content added by this handler, those rules
#         will be ignored.
# NOTE 2: The system must be rebooted after application of this handler.
#         The configuration-changes this handler effects only become
#         active with a reboot. Scanning tools should still fail to
#         certify the system if they are (re)run prior to a reboot.
#
#################################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "SCAP Recommendation: "
diag_out "  Make the audit subsystem's"
diag_out "  configuration immutable"
diag_out "NOTE: Not yet accepted into STIGs"
diag_out "----------------------------------"

