# STIG ID:	RHEL-07-030650
# Rule ID:	SV-86777r5_rule
# Vuln ID:	V-72153
# SRG ID:	SRG-OS-000042-GPOS-00020
# Finding Level:	medium
#
# Rule Summary:
#	All uses of the gpasswd command must be audited.
#
# CCI-000135
# CCI-000172
# CCI-002884
#    NIST SP 800-53 :: AU-3 (1)
#    NIST SP 800-53A :: AU-3 (1).1 (ii)
#    NIST SP 800-53 Revision 4 :: AU-3 (1)
#    NIST SP 800-53 :: AU-12 c
#    NIST SP 800-53A :: AU-12.1 (iv)
#    NIST SP 800-53 Revision 4 :: AU-12 c
#    NIST SP 800-53 Revision 4 :: MA-4 (1) (a)
#
#################################################################
{%- set stig_id = 'RHEL-07-030650' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set ruleFile = '/etc/audit/rules.d/priv_acts.rules' %}
{%- set sysuserMax = salt['cmd.shell']("awk '/SYS_UID_MAX/{ IDVAL = $2 + 1} END { print IDVAL }' /etc/login.defs") %}
{%- set path2mon = '/usr/bin/gpasswd' %}
{%- set key2mon = 'privileged-passwd' %}

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
    - pattern: '^-a always,exit -F path={{ path2mon }}.*$'
    - repl: '-a always,exit -F path={{ path2mon }} -F auid>={{ sysuserMax }} -F auid!=4294967295 -k {{ key2mon }}'
    - append_if_not_found: True
{%- endif %}
