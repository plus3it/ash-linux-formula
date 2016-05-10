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

{%- set helperLoc = 'ash-linux/el6/SCAPonly/low/files' %}
{%- set scapId = 'CCE-26612-2' %}
{%- set audRulCfg = '/etc/audit/audit.rules' %}

script_{{ scapId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ scapId }}.sh
    - cwd: '/root'

# Set the immutability flag at the end of {{ audRulCfg }}
lock_{{ scapId }}-{{ audRulCfg }}:
  file.append:
    - name: '{{ audRulCfg }}'
    - text: |
        
        # Set immutable flag on {{ audRulCfg }} per SCAP-ID {{ scapId }}
        -e 2
    - unless: 'tail -1 {{ audRulCfg }} | grep -E "^-e 2"'
