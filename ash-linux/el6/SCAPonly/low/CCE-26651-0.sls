# This Salt test/lockdown implements a SCAP item that has already been
# merged into the DISA-published STIGS
#
# Rule ID:
# - audit_rules_file_deletion_events
#
# Security identifiers:
# - CCE-26651-0
#
# Rule Summary: Ensure auditd Collects File Deletion Events by User
#
# Rule Text:
#
#################################################################

{%- set helperLoc = 'ash-linux/el6/SCAPonly/low/files' %}
{%- set scapId = 'CCE-26651-0' %}
{%- set stigId = 'V-38575' %}

script_{{ scapId }}-describe:
  cmd.run:
    - name: 'printf "
************************************************\n
* NOTE: {{ scapId }} already covered by handler *\n
*       for STIG-ID {{ stigId }}                    *\n
************************************************\n"'
