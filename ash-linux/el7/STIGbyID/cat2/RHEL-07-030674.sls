# Finding ID:	RHEL-07-030674
# Version:	RHEL-07-030674_rule
# SRG ID:	SRG-OS-000471-GPOS-00216
# Finding Level:	medium
#
# Rule Summary:
#	All uses of the modprobe command must be audited.
#
# CCI-000172
#    NIST SP 800-53 :: AU-12 c
#    NIST SP 800-53A :: AU-12.1 (iv)
#    NIST SP 800-53 Revision 4 :: AU-12 c
#
#################################################################
{%- set stig_id = 'RHEL-07-030674' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set ruleFile = '/etc/audit/rules.d/audit.rules' %}
{%- set path2mon = '/sbin/modprobe' %}
{%- set key2mon = 'module-change' %}

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
touch_{{ stig_id }}-{{ ruleFile }}:
  file.touch:
    - name: '{{ ruleFile }}'
    - unless:
      - 'test -e {{ ruleFile }}'

file_{{ stig_id }}-{{ ruleFile }}:
  file.replace:
    - name: '{{ ruleFile }}'
    - pattern: '^-w {{ path2mon }}.*$'
    - repl: '-w {{ path2mon }} -F auid!=4294967295 -k {{ key2mon }}'
    - append_if_not_found: True
{%- endif %}
