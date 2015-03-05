# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Rule ID: audit_manual_logon_edits
# - audit_manual_logon_edits
#
# Security identifiers:
# - CCE-26691-6
#
# Rule Summary: Record Attempts to Alter Logon and Logout Events
#
# Rule Text: The audit system already collects login info for all users 
#            and root. This information is stored primarily in 
#            '/var/log/faillog' and '/var/log/lastlog'. Manual editing 
#            of these files may indicate nefarious activity, such as an 
#            attacker attempting to remove evidence of an intrusion. 
#            Configure the audit serice to monitor these files attempts 
#            to edit their contents.
#
#################################################################

{%- set helperLoc = 'ash-linux/SCAPonly/low/files' %}
{%- set scapId = 'CCE-26691-6' %}
{%- set logonFiles = [
  '/var/log/faillog',
  '/var/log/faillog',
] %}

script_{{ scapId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ scapId }}.sh
    - cwd: '/root'


