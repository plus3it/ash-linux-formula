# STIG ID:	RHEL-07-030350
# Rule ID:	SV-86717r3_rule
# Vuln ID:	V-72093
# SRG ID:	SRG-OS-000343-GPOS-00134
# Finding Level:	medium
#
# Rule Summary:
#	The operating system must immediately notify the System
#	Administrator (SA) and Information System Security Officer
#	(ISSO) (at a minimum) when the threshold for the repository
#	maximum audit record storage capacity is reached.
#
# CCI-001855
#    NIST SP 800-53 Revision 4 :: AU-5 (1)
#
#################################################################
{%- set stig_id = 'RHEL-07-030350' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set audCfg = '/etc/audit/auditd.conf' %}
{%- set parmName = 'action_mail_acct'%}
{%- set alrtdest = salt.pillar.get('ash-linux:lookup:notifier-email', 'root') %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Handler for {{ stig_id }} has been selected for skip.''\n"'
    - stateful: True
    - cwd: /root
{%- else %}
  {%- if salt.file.file_exists(audCfg) %}
file_{{ stig_id }}-{{ parmName }}:
  file.replace:
    - name: '{{ audCfg }}'
    - pattern: '^\s{{ parmName }}.*$'
    - repl: '{{ parmName }} = {{ alrtdest }}'
    - append_if_not_found: True
  {%- else %}
file_{{ stig_id }}-{{ parmName }}:
  file.append:
    - name: '{{ audCfg }}'
    - text: '{{ parmName }} = {{ alrtdest }}'
    - makedirs: True
  {%- endif %}
{%- endif %}
