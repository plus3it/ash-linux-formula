# Finding ID:	RHEL-07-030620
# Version:	RHEL-07-030620_rule
# SRG ID:	SRG-OS-000392-GPOS-00172
# Finding Level:	medium
#
# Rule Summary:
#	The operating system must generate audit records for all
#	successful account access events.
#
# CCI-000172
# CCI-002884
# CCI-000126
#    NIST SP 800-53 :: AU-12 c
#    NIST SP 800-53A :: AU-12.1 (iv)
#    NIST SP 800-53 Revision 4 :: AU-12 c
#    NIST SP 800-53 Revision 4 :: MA-4 (1) (a)
#    NIST SP 800-53 :: AU-2 d
#    NIST SP 800-53A :: AU-2.1 (v)
#    NIST SP 800-53 Revision 4 :: AU-2 d
#
#################################################################
{%- set stig_id = 'RHEL-07-030620' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set audit_cfg_file = '/etc/audit/rules.d/audit.rules' %}
{%- set watchFile = '/var/log/lastlog' %}

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
file_{{ stig_id }}-{{ audit_cfg_file }}:
  file.replace:
    - name: '{{ audit_cfg_file }}'
    - pattern: '^.*{{ watchFile }}.*$'
    - repl: '-w {{ watchFile }} -p wa -k logins'
    - append_if_not_found: True
{%- endif %}
