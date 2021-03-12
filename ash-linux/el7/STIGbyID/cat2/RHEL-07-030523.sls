# Finding ID:	RHEL-07-030523
# Version:	RHEL-07-030523_rule
# SRG ID:	SRG-OS-000037-GPOS-00015
# Finding Level:	medium
#
# Rule Summary:
#	The operating system must generate audit records containing the
#	full-text recording of modifications to sudo configuration files.
#
# CCI-000130
# CCI-000135
# CCI-000172
# CCI-002884
#    NIST SP 800-53 :: AU-3
#    NIST SP 800-53A :: AU-3.1
#    NIST SP 800-53 Revision 4 :: AU-3
#    NIST SP 800-53 :: AU-3 (1)
#    NIST SP 800-53A :: AU-3 (1).1 (ii)
#    NIST SP 800-53 Revision 4 :: AU-3 (1)
#    NIST SP 800-53 :: AU-12 c
#    NIST SP 800-53A :: AU-12.1 (iv)
#    NIST SP 800-53 Revision 4 :: AU-12 c
#    NIST SP 800-53 Revision 4 :: MA-4 (1) (a)
#
#################################################################
{%- set stig_id = 'RHEL-07-030523' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set audit_cfg_file = '/etc/audit/rules.d/audit.rules' %}
{%- set watchFile = '/etc/sudoers' %}
{%- set watchType = 'privileged-actions' %}

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
    - repl: '-w {{ watchFile }} -p wa -k {{ watchType }}'
    - append_if_not_found: True
{%- endif %}
