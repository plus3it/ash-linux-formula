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

{%- set helperLoc = 'ash-linux/el6/SCAPonly/low/files' %}
{%- set scapId = 'CCE-26691-6' %}
{%- set audRulCfg = '/etc/audit/audit.rules' %}
{%- set logonFiles = [
  '/var/log/faillog',
  '/var/log/lastlog',
] %}
{%- set audit_options = '-p wa -k logins' %}

script_{{ scapId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ scapId }}.sh
    - cwd: '/root'

######################################################################
# Will probably want to look at method to do all the edits in one pass
# as current method limits rollback capability
######################################################################

# Iterate through our logonFiles list
{%- for file in logonFiles %}

  # (Re-)Construct our audit-rule string with each pass
  {%- set rule = '-w' + ' ' + file + ' ' + audit_options %}

  # See if the rule already exists
  {%- if not salt['cmd.shell']('grep -c -E -e "' + rule + '" ' + audRulCfg ) == '0' %}

addRule_{{ scapId }}-auditRules_{{ file }}:
  cmd.run:
    - name: 'echo "Appropriate audit rule already in place"'

  {%- else %}

addRule_{{ scapId }}-auditRules_{{ file }}:
  file.replace:
    - name: '{{ audRulCfg }}'
    - pattern: '^.*{{ file }}.*$'
    - repl: '{{ rule }}'

file_{{ scapId }}-auditRules_{{ file }}:
  file.append:
    - name: '{{ audRulCfg }}'
    - text: |
        
        # Monitor {{ file }} for changes (per SCAP-ID {{ scapId }})
        {{ rule }}
  {%- endif %}
{%- endfor %}
